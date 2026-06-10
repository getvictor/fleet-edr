// Playwright fixture for UAT plan layer L4 (M5): seed agent-shaped state via the same YAML scenarios the Go fakeagent library consumes
// (test/fakeagent/scenarios/), rather than directly seeding the events table via SQL like fixtures/db.ts does. The fixture enrols a
// fresh host via /api/enroll, materialises the scenario's timeline into wire envelopes that match schema/events.json byte-for-byte,
// then POSTs them to /api/events with the minted bearer token. End-to-end this exercises the server's host-token middleware +
// ingestion + processor, which gives UI tests realistic host / process / event data without the headless agent in the loop.
//
// Why not go through the M2 headless binary's POST /event control plane?
//   - The agent's queue + uploader path is already covered end-to-end by M4 (test/integration/agentserver).
//   - L4 is about UI-facing tests; the data shape is the contract that matters, not the queue mechanics.
//   - Running the headless binary alongside Playwright would mean process orchestration in playwright.config.ts plus a single shared
//     host_id across the suite (the binary enrols once at startup). Per-test enrollment is much cleaner for UI specs that want
//     isolated state.
//
// Why not port the Go fakeagent library to TypeScript? The YAML scenarios are the single source of truth shared between Go and TS;
// the envelope-shaping logic is small and stable (seven event types: exec, fork, exit, open, network_connect, dns_query,
// snapshot_heartbeat, the same set as the Go side). Duplicating ~80 LOC of mapping is cheaper than a Go/Node FFI bridge.
//
// Wire-precision note: timestamp_ns is computed with BigInt so the value matches schema/events.json's integer type at full int64
// precision, then emitted as an unquoted JSON number via a custom serialiser below. Plain `Number(epochMs) * 1e6` would silently
// lose ~3 lower digits for current-epoch timestamps (epoch_ns ~1.8e18 > MAX_SAFE_INTEGER 9e15), drifting from the Go path's int64
// arithmetic. event_id is `crypto.randomUUID()` to satisfy schema/events.json's `format: uuid` constraint.

import { test as base, request as playwrightRequest, APIRequestContext } from "@playwright/test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as crypto from "node:crypto";
import * as yaml from "js-yaml";

const SCENARIOS_DIR = path.join(__dirname, "..", "..", "fakeagent", "scenarios");

// EnrollSecret matches Taskfile.yml's `task dev:server*` env block (`EDR_ENROLL_SECRET: dev-enroll-secret`). Keep in sync if the dev
// secret ever changes. Hardcoded because every test in this suite already targets the dev server explicitly.
const ENROLL_SECRET = "dev-enroll-secret";

// --- Scenario shape (mirrors test/fakeagent/fakeagent.go's Scenario struct) ---

export interface ScenarioHost {
  id: string;
  hostname?: string;
  os?: string;
}

export interface ScenarioEvent {
  at: string; // "10ms", "5s", "1h", parsed via parseGoDuration below.
  type: string;
  // Type-specific fields. Only those relevant to `type` are honoured.
  pid?: number;
  ppid?: number;
  uid?: number;
  gid?: number;
  child_pid?: number;
  parent_pid?: number;
  path?: string;
  args?: string[];
  cwd?: string;
  exit_code?: number;
  exit_reason?: string; // schema/events.json exit_payload.exit_reason, matches the Go ScenarioEvent struct.
  flags?: number;
  protocol?: string;
  direction?: string;
  local_address?: string;
  local_port?: number;
  remote_address?: string;
  remote_port?: number;
  query_name?: string;
  query_type?: string;
  response_addresses?: string[];
}

export interface Scenario {
  name: string;
  mitre?: string;
  host: ScenarioHost;
  timeline: ScenarioEvent[];
}

// --- Envelope shape (mirrors schema/events.json) ---

export interface Envelope {
  event_id: string;
  host_id: string;
  /**
   * Nanoseconds since Unix epoch. Stored as BigInt so values past JS's MAX_SAFE_INTEGER (9e15), which every current-epoch
   * nanosecond timestamp exceeds, retain int64 precision. Serialised to JSON as an unquoted number via the BigInt-aware
   * stringify helper below.
   */
  timestamp_ns: bigint;
  event_type: string;
  payload: Record<string, unknown>;
}

// --- Fixture API ---

export interface AgentScenarioResult {
  /** The host_id under which the scenario's events were posted. Use this in subsequent assertions. */
  hostId: string;
  /** Number of envelopes that landed at /api/events (HTTP 200). */
  eventsPosted: number;
  /** Bearer token the fixture used; available to the test if it needs to make follow-up host-scoped requests. */
  hostToken: string;
}

export interface AgentScenarioOptions {
  /** Override the scenario's host.id without editing the YAML. Useful when a single test wants N hosts from one scenario. */
  hostIdOverride?: string;
  /** Start time for the timeline. Defaults to `new Date()` at call time. Tests that need deterministic timestamps pass a fixed value. */
  startTime?: Date;
}

export interface BatchEnrollOptions {
  /**
   * Scenario YAML name (e.g. "quiet-host.yaml") whose timeline is replayed for every host in the batch. Defaults to
   * "quiet-host.yaml" so each host materialises with a single snapshot_heartbeat event: enough to appear in the host list but
   * cheap to ingest. Specs that want per-host event variety (e.g. host-list-event-count) override this.
   */
  scenarioFile?: string;
}

export interface BatchEnrollResult {
  hostId: string;
  hostToken: string;
  eventsPosted: number;
}

export interface AgentFixtures {
  agent: {
    /** Load + post one scenario in one call. Returns once /api/events returns 200 for every envelope. */
    runScenario(name: string, opts?: AgentScenarioOptions): Promise<AgentScenarioResult>;
    /**
     * Enrol `count` hosts in parallel and feed each one through the configured scenario. Returns an array of results in
     * deterministic order (i.e. result[i] corresponds to the i-th host). Used by the host-list pagination + multi-host specs
     * that need to populate enough rows to exercise the UI's listing behaviour.
     *
     * Parallelism is bounded by the dev server's concurrency (sufficient for batches of tens; for hundreds, the caller should
     * chunk explicitly). Each host gets a fresh `crypto.randomUUID()` host_id and the scenario's default hostname (the
     * /api/enroll endpoint validates hardware_uuid against a strict UUID regex, so the host_id has to stay shaped that way -
     * if a future spec needs per-host hostname variation, that knob lands in BatchEnrollOptions then).
     */
    enrollHostsBatch(count: number, opts?: BatchEnrollOptions): Promise<BatchEnrollResult[]>;
  };
}

// --- Implementation ---

export const test = base.extend<AgentFixtures>({
  agent: async ({ baseURL }, use) => {
    if (!baseURL) {
      throw new Error("agent fixture requires Playwright baseURL to be set in playwright.config.ts");
    }
    const ctx = await playwrightRequest.newContext({ baseURL, ignoreHTTPSErrors: true });
    try {
      const runScenario = async (name: string, opts?: AgentScenarioOptions): Promise<AgentScenarioResult> => {
        const scenario = await loadScenario(name);
        const hostId = opts?.hostIdOverride ?? scenario.host.id;
        const hostname = scenario.host.hostname ?? "playwright.lab.local";
        const hostToken = await enrollHost(ctx, hostId, hostname);
        const envelopes = generateEnvelopes(scenario, hostId, opts?.startTime ?? new Date());
        // stringifyEnvelopes serialises BigInt timestamp_ns as an unquoted JSON number. Passing a pre-serialised string to ctx.post's
        // `data` field means Playwright sends it verbatim instead of running it through its own JSON.stringify (which would call
        // .toString() on the BigInt and throw, or produce a string-quoted timestamp_ns that the server would then reject).
        const resp = await ctx.post("/api/events", {
          data: stringifyEnvelopes(envelopes),
          headers: { Authorization: `Bearer ${hostToken}`, "Content-Type": "application/json" },
        });
        if (!resp.ok()) {
          const body = await resp.text();
          throw new Error(`POST /api/events for ${hostId}: HTTP ${resp.status()}: ${body}`);
        }
        return { hostId, eventsPosted: envelopes.length, hostToken };
      };

      await use({
        runScenario,
        async enrollHostsBatch(count: number, opts?: BatchEnrollOptions): Promise<BatchEnrollResult[]> {
          if (count <= 0) {
            throw new Error(`enrollHostsBatch: count must be > 0, got ${count}`);
          }
          const scenarioFile = opts?.scenarioFile ?? "quiet-host.yaml";
          // Each host gets a fresh UUID. Running in parallel via Promise.all keeps wall time bounded; the dev server handles
          // tens of concurrent enrolments comfortably (the existing rate limit is 1000/min via integration.Setup's
          // EnrollRatePerMinute, and dev's default is similarly generous).
          const tasks = Array.from({ length: count }, async () => {
            const hostId = crypto.randomUUID();
            const r = await runScenario(scenarioFile, { hostIdOverride: hostId });
            return { hostId: r.hostId, hostToken: r.hostToken, eventsPosted: r.eventsPosted };
          });
          return Promise.all(tasks);
        },
      });
    } finally {
      await ctx.dispose();
    }
  },
});

// loadScenario reads + parses a YAML file from the shared corpus. Returns the typed Scenario shape.
export async function loadScenario(name: string): Promise<Scenario> {
  const file = path.isAbsolute(name) ? name : path.join(SCENARIOS_DIR, name);
  const raw = await fs.readFile(file, "utf-8");
  const parsed = yaml.load(raw) as Scenario;
  if (!parsed?.name) {
    throw new Error(`scenario ${file}: missing 'name' field`);
  }
  if (!parsed.host?.id) {
    throw new Error(`scenario ${file}: missing 'host.id' field`);
  }
  if (!Array.isArray(parsed.timeline) || parsed.timeline.length === 0) {
    throw new Error(`scenario ${file}: 'timeline' must be a non-empty array`);
  }
  return parsed;
}

// enrollHost calls /api/enroll with the dev secret and returns the issued bearer token. hostId must be a canonical UUID; the server's
// endpoint service rejects anything else.
async function enrollHost(ctx: APIRequestContext, hostId: string, hostname: string): Promise<string> {
  const resp = await ctx.post("/api/enroll", {
    data: {
      enroll_secret: ENROLL_SECRET,
      hardware_uuid: hostId,
      hostname,
      agent_version: "playwright-l4-agent-fixture",
      os_version: "macOS 26.0",
    },
  });
  if (!resp.ok()) {
    const body = await resp.text();
    throw new Error(`/api/enroll for ${hostId}: HTTP ${resp.status()}: ${body}`);
  }
  const json = (await resp.json()) as { host_id?: string; host_token?: string };
  if (!json.host_token) {
    throw new Error(`/api/enroll for ${hostId}: response missing host_token: ${JSON.stringify(json)}`);
  }
  return json.host_token;
}

// generateEnvelopes materialises a scenario's timeline into wire envelopes. The shape matches schema/events.json and the Go
// fakeagent.Envelopes function so the two paths can't drift. event_id is a canonical (lowercase, hyphenated) UUID per the schema's
// `format: uuid` constraint. timestamp_ns is computed with BigInt because every current-epoch nanosecond timestamp exceeds JS's
// Number.MAX_SAFE_INTEGER; storing as a plain Number would silently round and diverge from Go's int64.
export function generateEnvelopes(scenario: Scenario, hostId: string, startTime: Date): Envelope[] {
  const startNs = BigInt(startTime.getTime()) * 1_000_000n;
  return scenario.timeline.map((ev) => ({
    event_id: crypto.randomUUID(),
    host_id: hostId,
    timestamp_ns: startNs + parseGoDuration(ev.at),
    event_type: ev.type,
    payload: buildPayload(ev),
  }));
}

// stringifyEnvelopes serialises a batch of envelopes to a JSON string with BigInt timestamp_ns emitted as an UNQUOTED JSON number,
// matching the integer type schema/events.json declares. A sentinel + post-process regex is the only zero-dep path; the alternative
// (JSON.stringify replacer returning a number) doesn't help because JS converts BigInt to Number at the toJSON boundary, losing the
// precision we went to BigInt to preserve. The sentinel chars are chosen to be both regex-safe and JSON-impossible so the regex
// can't accidentally match real payload content.
export function stringifyEnvelopes(envelopes: Envelope[]): string {
  const sentinel = "@@BIGINT@@";
  const raw = JSON.stringify(envelopes, (_k, v) =>
    typeof v === "bigint" ? `${sentinel}${v.toString()}${sentinel}` : v,
  );
  return raw.replace(/"@@BIGINT@@(\d+)@@BIGINT@@"/g, "$1");
}

// buildPayload picks the right field subset for each event_type and emits exactly the schema/events.json-required shape. Order +
// shape mirrors test/fakeagent/feeder.go's buildPayload so the two implementations stay byte-identical for the same input.
function buildPayload(ev: ScenarioEvent): Record<string, unknown> {
  switch (ev.type) {
    case "exec":
      return {
        pid: ev.pid ?? 0,
        ppid: ev.ppid ?? 0,
        path: ev.path ?? "",
        args: ev.args ?? [],
        cwd: ev.cwd ?? "",
        uid: ev.uid ?? 0,
        gid: ev.gid ?? 0,
      };
    case "fork":
      return { child_pid: ev.child_pid ?? 0, parent_pid: ev.parent_pid ?? 0 };
    case "exit": {
      const p: Record<string, unknown> = { pid: ev.pid ?? 0, exit_code: ev.exit_code ?? 0 };
      // exit_reason is schema/events.json's optional discriminator between "event" (kernel-observed) and "host_reconciled" (synthetic).
      // Only emit when the scenario set it so consumers see schema/events.json's "absent" semantics for default scenarios.
      if (ev.exit_reason) p.exit_reason = ev.exit_reason;
      return p;
    }
    case "open":
      return { pid: ev.pid ?? 0, path: ev.path ?? "", flags: ev.flags ?? 0 };
    case "network_connect": {
      const p: Record<string, unknown> = {
        pid: ev.pid ?? 0,
        protocol: ev.protocol ?? "tcp",
        direction: ev.direction ?? "outbound",
        remote_address: ev.remote_address ?? "",
        remote_port: ev.remote_port ?? 0,
      };
      if (ev.local_address) p.local_address = ev.local_address;
      // !== undefined so an explicitly-provided local_port: 0 isn't dropped by JS truthy semantics. Same shape for the address
      // wouldn't matter (empty string is falsy + meaningless), so the local_address truthy check stays.
      if (ev.local_port !== undefined) p.local_port = ev.local_port;
      return p;
    }
    case "dns_query": {
      const p: Record<string, unknown> = {
        pid: ev.pid ?? 0,
        query_name: ev.query_name ?? "",
        query_type: ev.query_type ?? "A",
      };
      if (ev.response_addresses) p.response_addresses = ev.response_addresses;
      if (ev.protocol) p.protocol = ev.protocol;
      return p;
    }
    case "snapshot_heartbeat":
      return { pid: ev.pid ?? 0 };
    default:
      throw new Error(`generateEnvelopes: unknown event_type ${JSON.stringify(ev.type)}`);
  }
}

// parseGoDuration accepts the Go time.Duration string form ("10ms", "5s", "1h", "100us"). Returns nanoseconds as a BigInt so the
// caller can add the value to a BigInt epoch without precision loss. Fractional input is TRUNCATED toward zero at the nanosecond
// boundary via integer division (no float intermediates), so "1.5s" yields exactly 1_500_000_000n and "0.1234567899ns" yields 0n.
// Scenarios written today only use round numbers of ns/us/ms/s, so the truncation never bites. If a scenario ever needs sub-ns
// rounding, that's a separate change to add an explicit round-half-up step.
function parseGoDuration(input: string): bigint {
  const match = /^(\d+)(?:\.(\d+))?(ns|us|µs|ms|s|m|h)$/.exec(input);
  if (!match) {
    throw new Error(`parseGoDuration: cannot parse ${JSON.stringify(input)}`);
  }
  const unitNs: Record<string, bigint> = {
    ns: 1n,
    us: 1_000n,
    "µs": 1_000n,
    ms: 1_000_000n,
    s: 1_000_000_000n,
    m: 60n * 1_000_000_000n,
    h: 3600n * 1_000_000_000n,
  };
  const factor = unitNs[match[3]];
  const wholeNs = BigInt(match[1]) * factor;
  if (!match[2]) {
    return wholeNs;
  }
  // Fractional part: "1.5s" -> wholeNs=1e9, fracDigits="5", scale 10^1=10. Add (5 * factor) / 10 in integer arithmetic.
  const fracDigits = match[2];
  const scale = 10n ** BigInt(fracDigits.length);
  return wholeNs + (BigInt(fracDigits) * factor) / scale;
}

export { expect } from "@playwright/test";
