import * as crypto from "node:crypto";
import mysql, { Connection } from "mysql2/promise";

// Dev DB matches Taskfile's dev:server* env block: root user, empty
// password, port 33306. Keep this constant in sync with
// Taskfile.yml's EDR_DSN.
//
// The schema is overridable for the same reason playwright.config.ts's port is: this repository is worked as two worktrees on one
// machine, and lane B runs its server on 8089 against the `edr2` schema. Pointing only the port at lane B while this stayed
// hardcoded to `edr` would be worse than not running at all, because the suite would drive one lane's server and reset the OTHER
// lane's auth tables. E2E_PORT and E2E_DB must therefore be set together, which assertLaneEnv below enforces rather than requests.
/**
 * LANE_SCHEMA is the MySQL and ClickHouse schema this run belongs to, and the single place that decision is made.
 *
 * Exported because playwright.config.ts needs the same answer to tell the server it spawns which lane it is in. Three independent
 * copies of `process.env.E2E_DB ?? "edr"` is how a run ends up driving one lane's server while resetting another's tables, which
 * is the exact hazard assertLaneEnv exists to prevent, arrived at by drift instead of by a typo.
 */
export const LANE_SCHEMA = process.env.E2E_DB ?? "edr";

/**
 * assertLaneEnv refuses a half-configured lane override.
 *
 * Setting only E2E_PORT points the browser at one worktree's server while resetDB deletes the OTHER worktree's sessions, users and
 * audit rows: a destructive cross-lane action that looks like an ordinary test run. Setting only E2E_DB is the mirror image and is
 * merely wrong rather than destructive, but it is rejected too, because a suite reading one lane and driving another produces
 * failures that take far longer to understand than this error does. Documented as a required pair before; enforced now.
 */
export function assertLaneEnv(): void {
  const port = process.env.E2E_PORT;
  const db = process.env.E2E_DB;
  const advice = "For lane B use: E2E_PORT=8089 E2E_DB=edr2";

  // Defined-ness, not truthiness. `E2E_PORT=""` is falsy but not nullish, so a truthiness pair-check passed it while the `??`
  // defaults below did NOT apply, leaving port 0 and an empty schema. Both are "the variable is set", so both must be validated.
  const portSet = port !== undefined;
  const dbSet = db !== undefined;
  if (portSet !== dbSet) {
    throw new Error(
      `E2E_PORT and E2E_DB must be set together (got E2E_PORT=${port ?? "unset"}, E2E_DB=${db ?? "unset"}). ` +
        "Setting only one drives one worktree's server while resetting the other worktree's auth tables. " +
        advice,
    );
  }
  if (!portSet) return;

  // Paired but invalid is the other half of the same hazard, and quieter: a non-numeric port becomes `https://localhost:NaN` and
  // an empty schema becomes a connection to the server's default, both of which fail in ways that look like anything but a typo.
  const parsed = Number(port);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`E2E_PORT must be an integer port between 1 and 65535 (got ${JSON.stringify(port)}). ${advice}`);
  }
  if (db === "") {
    throw new Error(`E2E_DB must name a schema (got an empty string). ${advice}`);
  }

  // Paired, valid, and MISMATCHED is the last shape, and the most destructive one now that the suite spawns its own server.
  // `E2E_PORT=8089 E2E_DB=edr` passes every check above: it boots a lane B listener against lane A's schema and then deletes lane
  // A's sessions, users and audit rows, which is the cross-lane wipe the pair rule was written to stop, reached by transposing
  // one value rather than by omitting one. The lanes are a closed set of two, so the pairing is checkable rather than advisory.
  const expected = LANE_TO_SCHEMA.get(parsed);
  if (expected === undefined) {
    throw new Error(`E2E_PORT=${parsed} is not a lane this repository has (${[...LANE_TO_SCHEMA.keys()].join(", ")}). ${advice}`);
  }
  if (db !== expected) {
    throw new Error(
      `E2E_PORT=${parsed} belongs to schema ${expected}, not ${JSON.stringify(db)}. Running them crossed drives one worktree's ` +
        `server while resetting the other worktree's auth tables. ${advice}`,
    );
  }
}

/**
 * LANE_TO_SCHEMA is the machine's two worktrees: lane A on 8088 against `edr`, lane B on 8089 against `edr2`.
 *
 * A closed set rather than a convention, because the pair is what makes a run safe and nothing else can check it. Adding a third
 * lane means adding it here, which is the right place to notice that its schema has to exist.
 */
const LANE_TO_SCHEMA = new Map<number, string>([
  [8088, "edr"],
  [8089, "edr2"],
]);

assertLaneEnv();

const DEV_DSN = {
  host: "127.0.0.1",
  port: 33306,
  user: "root",
  password: "",
  database: LANE_SCHEMA,
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

// Dev ClickHouse archive HTTP endpoint, matching docker-compose.yml's clickhouse service (8123 published on 18123). The default user
// has an empty password (CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT), so no auth header is needed. database=edr selects the archive database
// the server creates (matching EDR_CLICKHOUSE_DSN's /edr path); the connection's implicit database is `default`, where `events` does
// not live.
const CLICKHOUSE_HTTP = `http://127.0.0.1:18123/?database=${LANE_SCHEMA}`;

// queryClickHouse runs a read-only query against the dev ClickHouse event archive (ADR-0015: events live here, not MySQL) over its HTTP
// interface and returns the rows as parsed objects. No extra npm dependency: the HTTP interface speaks plain SQL. count() and other
// UInt64 columns arrive as JSON strings (JSONEachRow quotes them to preserve precision), so callers wrap them in Number().
export async function queryClickHouse<T = Record<string, unknown>>(sql: string): Promise<T[]> {
  const res = await fetch(CLICKHOUSE_HTTP, { method: "POST", body: `${sql} FORMAT JSONEachRow` });
  if (!res.ok) {
    throw new Error(`clickhouse query failed (${res.status}): ${await res.text()}`);
  }
  const text = await res.text();
  return text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as T);
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
  const [rows] = await db.query<mysql.RowDataPacket[]>("SELECT id FROM users WHERE email = 'admin@fleet-edr.local' LIMIT 1");
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
export async function promote(db: Connection, email: string, role: "admin" | "senior_analyst" | "auditor" | "super_admin"): Promise<void> {
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
export async function seedCriticalAlert(db: Connection, opts: { hostId: string; ruleId: string; title: string }): Promise<number> {
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

/**
 * forgeAdminSession inserts a session row for the seeded admin and returns the plaintext token for the `edr_session` cookie.
 *
 * This is the fast path for the dozen specs that need nothing more than "any signed-in admin". The break-glass ceremony they used
 * instead is rate-limited: `/admin/break-glass/setup` allows five submissions per minute globally and one sign-in spends TWO, so
 * ten sign-ins need twenty tokens from a bucket that starts with five and refills one every twelve seconds. Measured on a lane-B
 * dev server, roughly three of Phase 8's 4.8 minutes was the suite sitting still waiting for that bucket.
 *
 * Every column is written the way `sessions.Store.Create` writes it, because a forged session that differs from a real one lets a
 * spec pass against a shape the product never issues:
 *
 *   - `id` is SHA-256 of the RAW token bytes, not of their base64 text. That differs from `mintBootstrapToken` above, which hashes
 *     the encoded string, and getting the two confused produces a row that simply never matches.
 *   - the cookie carries unpadded base64url of those same raw bytes, which is what `api.EncodeToken` emits.
 *   - `csrf_token` is present and random. A session without one authenticates and then fails every state-changing request, which
 *     would look like an authorization bug in whichever spec first tried to POST.
 *   - `auth_method` is `local_password`, the value the break-glass ceremony sets, so these sessions keep the timeout class and the
 *     reauth-freshness behaviour the specs have today rather than quietly acquiring a longer-lived one.
 *   - all three timestamps are NOW(6), so the session is as fresh as one from a just-completed ceremony.
 *
 * `expires_at` deliberately does NOT try to reproduce the server's configured absolute timeout, and that is the safer choice
 * rather than a shortcut. Reproducing it would mean duplicating `DefaultBreakglassAbsoluteTimeout` and every override
 * (`EDR_BREAKGLASS_SESSION_ABSOLUTE_TIMEOUT`) in TypeScript, and the failure mode of getting that wrong is one-directional and
 * nasty: a forged session that outlives what the server would have issued keeps authorizing requests after a real one would
 * have expired, so a spec passes against a session the product would have rejected.
 *
 * Ten minutes is instead chosen to be far SHORTER than any timeout the product configures (the default absolute is one hour and
 * the default idle fifteen minutes), so drift can only ever make this fixture's sessions shorter-lived than real ones, which is
 * harmless. It is also enormous next to what a spec needs: the whole converted set runs in under ten seconds and the per-test
 * timeout is ninety.
 *
 * The caller sets the cookie and SHOULD verify once against `/api/session`; `signInAsAdminViaForgedSession` in auth.ts does both.
 *
 * Role bindings are not created here and must not be: `resetDB` deliberately preserves the seeded admin's bindings, and the server
 * ensures its super_admin binding at boot. Inserting one here would mask a missing binding rather than surface it.
 */
export async function forgeAdminSession(db: Connection): Promise<string> {
  const raw = crypto.randomBytes(32);
  const id = crypto.createHash("sha256").update(raw).digest();
  const csrf = crypto.randomBytes(32);

  const [rows] = await db.query<mysql.RowDataPacket[]>("SELECT id FROM users WHERE email = 'admin@fleet-edr.local' LIMIT 1");
  if (rows.length === 0) {
    throw new Error("forgeAdminSession: admin@fleet-edr.local not seeded yet");
  }

  await db.query(
    `INSERT INTO sessions (id, user_id, identity_id, auth_method, csrf_token,
                           created_at, last_seen_at, last_auth_at, expires_at)
     VALUES (?, ?, NULL, 'local_password', ?, NOW(6), NOW(6), NOW(6), NOW(6) + INTERVAL 10 MINUTE)`,
    [id, rows[0].id, csrf],
  );
  return raw.toString("base64url");
}
