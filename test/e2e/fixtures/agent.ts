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
// the envelope-shaping logic is small and stable (six event types covered here, same as the Go side). Duplicating ~80 LOC of mapping
// code is cheaper than maintaining a Go/Node FFI bridge.

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
  at: string; // "10ms", "5s", "1h" - parsed via parseGoDuration below.
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
  timestamp_ns: number;
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

export interface AgentFixtures {
  agent: {
    /** Load + post one scenario in one call. Returns once /api/events returns 200 for every envelope. */
    runScenario(name: string, opts?: AgentScenarioOptions): Promise<AgentScenarioResult>;
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
      await use({
        async runScenario(name: string, opts?: AgentScenarioOptions): Promise<AgentScenarioResult> {
          const scenario = await loadScenario(name);
          const hostId = opts?.hostIdOverride ?? scenario.host.id;
          const hostToken = await enrollHost(ctx, hostId, scenario.host.hostname ?? "playwright.lab.local");
          const envelopes = generateEnvelopes(scenario, hostId, opts?.startTime ?? new Date());
          const resp = await ctx.post("/api/events", {
            data: envelopes,
            headers: { Authorization: `Bearer ${hostToken}`, "Content-Type": "application/json" },
          });
          if (!resp.ok()) {
            const body = await resp.text();
            throw new Error(`POST /api/events for ${hostId}: HTTP ${resp.status()}: ${body}`);
          }
          return { hostId, eventsPosted: envelopes.length, hostToken };
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
// fakeagent.Envelopes function so the two paths can't drift. event_id is a 32-char hex random; timestamp_ns is startTime + at offset.
export function generateEnvelopes(scenario: Scenario, hostId: string, startTime: Date): Envelope[] {
  const startNs = startTime.getTime() * 1_000_000;
  return scenario.timeline.map((ev) => ({
    event_id: randomHex32(),
    host_id: hostId,
    timestamp_ns: startNs + parseGoDuration(ev.at),
    event_type: ev.type,
    payload: buildPayload(ev),
  }));
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
      if (ev.local_port) p.local_port = ev.local_port;
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

// parseGoDuration accepts the Go time.Duration string form ("10ms", "5s", "1h", "100us"). Returns nanoseconds. Supports the unit
// suffixes the M3 fakeagent + the rest of the EDR codebase actually use; rejects everything else with a clear error so a typo in a
// scenario file surfaces immediately rather than silently producing 0.
function parseGoDuration(input: string): number {
  const match = /^(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)$/.exec(input);
  if (!match) {
    throw new Error(`parseGoDuration: cannot parse ${JSON.stringify(input)}`);
  }
  const value = parseFloat(match[1]);
  const unitNs: Record<string, number> = {
    ns: 1,
    us: 1_000,
    "µs": 1_000,
    ms: 1_000_000,
    s: 1_000_000_000,
    m: 60 * 1_000_000_000,
    h: 3600 * 1_000_000_000,
  };
  return Math.round(value * unitNs[match[2]]);
}

// randomHex32 returns a 32-character lowercase hex string. Matches the Go fakeagent's default event_id generator.
function randomHex32(): string {
  return crypto.randomBytes(16).toString("hex");
}

export { expect } from "@playwright/test";
