import * as crypto from "node:crypto";
import mysql, { Connection } from "mysql2/promise";

// Dev DB matches Taskfile's dev:server* env block: root user, empty
// password, port 33306. Keep this constant in sync with
// Taskfile.yml's EDR_DSN.
const DEV_DSN = {
  host: "127.0.0.1",
  port: 33306,
  user: "root",
  password: "",
  database: "edr",
};

// Connect once per test; the connection is closed after each test via
// the Playwright fixture teardown. Pool would be nicer but a single
// connection keeps state-ownership obvious in test code.
export async function openDB(): Promise<Connection> {
  return mysql.createConnection({
    ...DEV_DSN,
    multipleStatements: true,
  });
}

// Wipe every operator-side table so the next test starts from a known
// shape. Leaves the schema in place (faster than DROP DATABASE +
// re-bootstrap) and PRESERVES the seeded admin user + its
// super_admin role binding so any post-test assertion that the admin
// can do admin things doesn't trip on a missing binding.
//
// Order matters: child rows before parents because of FK constraints.
// audit_events has no FK to users (actor_user_id is unconstrained on
// purpose so failed-auth attempts can record an attempted email even
// when no user exists), but every other table cascades.
export async function resetDB(db: Connection): Promise<void> {
  await db.query(`
    DELETE FROM webauthn_credentials;
    DELETE FROM sessions;
    DELETE FROM bootstrap_tokens;
    DELETE FROM role_bindings
     WHERE user_id NOT IN (SELECT id FROM (SELECT id FROM users WHERE email = 'admin@fleet-edr.local') t);
    DELETE FROM identities;
    DELETE FROM audit_events;
    DELETE FROM users WHERE email != 'admin@fleet-edr.local';
  `);
}

// Insert a fresh break-glass redemption token bound to the seeded
// admin user. Returns the plaintext for use in the redemption URL.
// The bootstrap_tokens table stores SHA-256(plaintext); the
// redemption flow recomputes the hash from the URL-supplied
// plaintext, so any random 32 bytes works.
export async function mintBootstrapToken(db: Connection): Promise<string> {
  const raw = crypto.randomBytes(32);
  const plaintext = raw.toString("base64url");
  const hash = crypto.createHash("sha256").update(plaintext).digest();
  // Find the seeded admin's id.
  const [rows] = await db.query<mysql.RowDataPacket[]>(
    "SELECT id FROM users WHERE email = 'admin@fleet-edr.local' LIMIT 1",
  );
  if (rows.length === 0) {
    throw new Error("mintBootstrapToken: admin@fleet-edr.local not seeded yet");
  }
  const userID = rows[0].id;
  await db.query(
    `INSERT INTO bootstrap_tokens (token_hash, user_id, kind, expires_at)
     VALUES (?, ?, 'breakglass_setup', NOW(6) + INTERVAL 1 HOUR)`,
    [hash, userID],
  );
  return plaintext;
}

// Promote a JIT-provisioned user to a non-default role. The OIDC JIT
// path lands every user in `analyst`; this helper inserts the
// additional role_bindings row a manual SQL promotion would. Used
// by the OIDC role-matrix tests to exercise senior_analyst /
// auditor without depending on wave-2 OIDC group-claim mapping.
export async function promote(
  db: Connection,
  email: string,
  role: "admin" | "senior_analyst" | "auditor" | "super_admin",
): Promise<void> {
  await db.query(
    `INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id)
     SELECT id, ?, 'global', '*' FROM users WHERE email = ?`,
    [role, email],
  );
}

// seedCriticalAlert inserts the minimum schema rows for the AlertList
// page to render a critical-severity alert (the only alert state that
// trips the chokepoint's reauth-required gate per
// server/identity/internal/authz/policy/edr.rego). Returns the alert
// id so the test can assert state transitions on it later. Used by
// the reauth-modal-retry spec; not part of rebuildQAState because
// most qa specs don't need detection-context fixtures.
//
// Schema dependency: alerts.process_id is FK-constrained to
// processes(id), so we seed a minimal process row first. processes
// itself has no FK constraints, so any host_id + pid + fork_time_ns
// combination is fine.
//
// alerts.subject is the dedup identity (ADR-0008 amendment); the unique
// key is (source, host_id, rule_id, subject), NOT process_id. For a
// process-backed alert the engine sets subject = the process_id string,
// so this raw-SQL seed must do the same: omitting it defaults subject
// to '' and a second seed for the same host+rule collides on
// uk_alerts_dedup. Each seed creates a fresh process row, so the
// per-process subject keeps re-seeds (Playwright retries) distinct.
export async function seedCriticalAlert(
  db: Connection,
  opts: { hostId: string; ruleId: string; title: string },
): Promise<number> {
  const procResult = await db.query(
    `INSERT INTO processes (host_id, pid, ppid, path, fork_time_ns)
     VALUES (?, 4242, 1, '/usr/bin/qa-test-process', ?)`,
    [opts.hostId, Date.now() * 1_000_000],
  );
  const processId = (procResult[0] as { insertId: number }).insertId;
  const alertResult = await db.query(
    `INSERT INTO alerts (host_id, rule_id, severity, title, description, process_id, subject)
     VALUES (?, ?, 'critical', ?, 'Seeded by Playwright reauth-modal spec', ?, ?)`,
    [opts.hostId, opts.ruleId, opts.title, processId, String(processId)],
  );
  return (alertResult[0] as { insertId: number }).insertId;
}
