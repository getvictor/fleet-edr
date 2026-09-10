import { describe, it, expect, vi, afterEach } from "vitest";
import {
  listDetectionExclusions,
  listDetectionRuleSettings,
  listDetectionRuleEvalStats,
  listDetectionRuleMatchCounts,
  createDetectionExclusion,
  deleteDetectionExclusion,
  upsertDetectionRuleSetting,
  DetectionConfigApiError,
  attachCsrfHeader,
} from "./api";

interface FakeResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: { get(name: string): string | null };
  clone(): FakeResponse;
  json(): Promise<unknown>;
}

function stubFetch(body: unknown, status = 200): ReturnType<typeof vi.fn> {
  const fake: FakeResponse = {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: { get: () => null },
    clone(): FakeResponse { return fake; },
    json(): Promise<unknown> { return Promise.resolve(body); },
  };
  const mock = vi.fn().mockResolvedValue(fake);
  vi.stubGlobal("fetch", mock);
  return mock;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

// A timestamp the validator accepts, so a malformed-row case fails for its own reason rather than for its placeholder.
const GOOD_TS = "2026-09-01T00:00:00Z";

describe("detection-config API client", () => {
  it("listDetectionExclusions unwraps the envelope", async () => {
    const mock = stubFetch({
      exclusions: [{
        id: 1, rule_id: "suspicious_exec", match_type: "path_glob", value: "*/x/*",
        host_group_id: 0, reason: "r", enabled: true, created_by: "user:1", created_at: "",
      }],
    });
    const out = await listDetectionExclusions();
    const [target] = mock.mock.calls[0] as [URL];
    expect(target.toString()).toContain("/api/v1/detection-config/exclusions");
    expect(out).toHaveLength(1);
  });

  // Regression: the server marshals an empty Go slice as JSON `null`, which crashed the page (`exclusions.length` on null)
  // before the client coalesced it. Caught only by real-server QA; unit tests had mocked `[]`.
  it("listDetectionExclusions tolerates a null envelope", async () => {
    stubFetch({ exclusions: null });
    expect(await listDetectionExclusions()).toEqual([]);
  });

  it("listDetectionRuleSettings tolerates a null envelope", async () => {
    stubFetch({ rule_settings: null });
    expect(await listDetectionRuleSettings()).toEqual([]);
  });

  // The component tests mock this client wholesale, so the query serialisation and the envelope REJECTION below have no other
  // coverage. Rejection, not coalescing: this endpoint deliberately refuses a malformed envelope where the sibling list endpoints
  // above coalesce one (a null envelope crashed the exclusions page once, which is why those coalesce).
  it("listDetectionRuleMatchCounts accepts a well-formed row", async () => {
    const row = { rule_id: "suspicious_exec", matches: 90, hosts: 3, last_seen: "2026-09-01T00:00:00Z" };
    stubFetch({ match_counts: [row], days: 7 });
    expect(await listDetectionRuleMatchCounts()).toEqual({ counts: [row], days: 7 });
  });

  // Zero is allowed even though the store should never emit it: rejecting it would be the client inventing a rule the server
  // does not promise, and a refused response renders as "unavailable", which is a worse answer than a truthful zero.
  it("listDetectionRuleMatchCounts accepts a zero count rather than inventing a floor", async () => {
    const row = { rule_id: "suspicious_exec", matches: 0, hosts: 0, last_seen: "2026-09-01T00:00:00Z" };
    stubFetch({ match_counts: [row], days: 7 });
    expect(await listDetectionRuleMatchCounts()).toEqual({ counts: [row], days: 7 });
  });

  it("listDetectionRuleMatchCounts omits the query when no window is given", async () => {
    const mock = stubFetch({ match_counts: [], days: 7 });
    const out = await listDetectionRuleMatchCounts();
    const [target] = mock.mock.calls[0] as [URL];
    expect(target.toString()).toContain("/api/v1/detection-config/rule-match-counts");
    expect(target.toString()).not.toContain("days=");
    expect(out).toEqual({ counts: [], days: 7 });
  });

  it("listDetectionRuleMatchCounts serialises an explicit window", async () => {
    const mock = stubFetch({ match_counts: [], days: 14 });
    await listDetectionRuleMatchCounts(14);
    const [target] = mock.mock.calls[0] as [URL];
    expect(target.toString()).toContain("days=14");
  });

  // The server reports the window it ACTUALLY covered, which the cap can make narrower than the one requested. The client must
  // pass that through rather than echo the caller's argument, or the UI labels the numbers with a period they do not cover.
  it("listDetectionRuleMatchCounts reports the server's window, not the requested one", async () => {
    stubFetch({ match_counts: [], days: 30 });
    expect(await listDetectionRuleMatchCounts(365)).toEqual({ counts: [], days: 30 });
  });

  // The opposite of the sibling endpoints above, deliberately. There an empty list is just an empty table; here the server always
  // normalises empty to [], so a missing array is a malformed response, and coalescing it to [] would render every rule as quiet,
  // which is the reading that gets a noisy rule promoted. Rejecting sends the caller down its unavailable path instead.
  //
  // Checked by shape rather than against one sentinel: an earlier version tested only for null, so an OMITTED key slipped through
  // as undefined and threw on .map() further out, failing the whole page rather than degrading one column. Each row below is a
  // shape that must be refused, not just the null one.
  for (const [name, envelope] of [
    ["null match_counts", { match_counts: null, days: 7 }],
    ["omitted match_counts", { days: 7 }],
    ["match_counts is not an array", { match_counts: { "0": {} }, days: 7 }],
    ["omitted days", { match_counts: [] }],
    ["days is not a number", { match_counts: [], days: "7" }],
    ["days is zero", { match_counts: [], days: 0 }],
    ["days is negative", { match_counts: [], days: -3 }],
    ["days is fractional", { match_counts: [], days: 1.5 }],
    // Each row is malformed in exactly ONE way, with every other field valid. A shared bad placeholder (last_seen: "x") made the
    // timestamp check reject these rows before the count check ran, so breaking the count guard changed nothing and the mutant
    // survived. A fixture that fails for the wrong reason tests the wrong guard.
    //
    // Row shapes. The first is the dangerous one: without a rule_id the caller keys the row under `undefined`, so every real rule
    // falls through to "not recorded" and the whole table reads as a quiet fleet, which is misleading evidence rather than a crash.
    ["a row with no rule_id", { match_counts: [{ matches: 1, hosts: 1, last_seen: "2026-09-01T00:00:00Z" }], days: 7 }],
    ["a row with an empty rule_id", { match_counts: [{ rule_id: "", matches: 1, hosts: 1, last_seen: GOOD_TS }], days: 7 }],
    ["a row missing matches", { match_counts: [{ rule_id: "r", hosts: 1, last_seen: GOOD_TS }], days: 7 }],
    ["a row missing hosts", { match_counts: [{ rule_id: "r", matches: 1, last_seen: GOOD_TS }], days: 7 }],
    ["a row missing last_seen", { match_counts: [{ rule_id: "r", matches: 1, hosts: 1 }], days: 7 }],
    // A complete row whose timestamp is not a date. Accepted as a string it would render the cell with recency silently absent,
    // which no well-formed response can produce, so the reader could not tell it from a rule that has none.
    ["a row whose last_seen is unparseable", { match_counts: [{ rule_id: "r", matches: 1, hosts: 1, last_seen: "not-a-date" }], days: 7 }],
    ["a row whose last_seen is empty", { match_counts: [{ rule_id: "r", matches: 1, hosts: 1, last_seen: "" }], days: 7 }],
    ["a row with a negative count", { match_counts: [{ rule_id: "r", matches: -1, hosts: 1, last_seen: GOOD_TS }], days: 7 }],
    ["a row with a fractional count", { match_counts: [{ rule_id: "r", matches: 1.5, hosts: 1, last_seen: GOOD_TS }], days: 7 }],
    ["a row that is not an object", { match_counts: ["nope"], days: 7 }],
    ["a row that is null", { match_counts: [null], days: 7 }],
    ["an empty row", { match_counts: [{}], days: 7 }],
  ] as [string, unknown][]) {
    it(`listDetectionRuleMatchCounts rejects a malformed envelope: ${name}`, async () => {
      stubFetch(envelope);
      await expect(listDetectionRuleMatchCounts()).rejects.toThrow(/malformed rule-match-counts/);
    });
  }

  // The eval-stats client is the same trust boundary as the match-count one and fails the same way, so it gets the same
  // treatment. The difference worth its own coverage is the evaluations floor: a row exists only because a rule evaluated, and the
  // mean is a division by that number, so 0 is malformed here where it is legitimate on the match-count side.
  it("listDetectionRuleEvalStats accepts a well-formed row", async () => {
    const row = {
      rule_id: "suspicious_exec", evaluations: 400, retryable_misses: 12,
      mean_eval_ns: 1_500_000, max_eval_ns: 90_000_000, total_eval_ns: 600_000_000, last_seen: GOOD_TS,
    };
    stubFetch({ eval_stats: [row], days: 7 });
    expect(await listDetectionRuleEvalStats()).toEqual({ stats: [row], days: 7 });
  });

  // Zero misses and zero timings are real: a rule can evaluate cheaply and never miss. Only `evaluations` has a floor.
  it("listDetectionRuleEvalStats accepts zero misses and zero timings", async () => {
    const row = {
      rule_id: "suspicious_exec", evaluations: 1, retryable_misses: 0,
      mean_eval_ns: 0, max_eval_ns: 0, total_eval_ns: 0, last_seen: GOOD_TS,
    };
    stubFetch({ eval_stats: [row], days: 7 });
    expect(await listDetectionRuleEvalStats()).toEqual({ stats: [row], days: 7 });
  });

  it("listDetectionRuleEvalStats omits the query when no window is given", async () => {
    const mock = stubFetch({ eval_stats: [], days: 7 });
    const out = await listDetectionRuleEvalStats();
    const [target] = mock.mock.calls[0] as [URL];
    expect(target.toString()).toContain("/api/v1/detection-config/rule-eval-stats");
    expect(target.toString()).not.toContain("days=");
    expect(out).toEqual({ stats: [], days: 7 });
  });

  it("listDetectionRuleEvalStats serialises an explicit window", async () => {
    const mock = stubFetch({ eval_stats: [], days: 14 });
    await listDetectionRuleEvalStats(14);
    const [target] = mock.mock.calls[0] as [URL];
    expect(target.toString()).toContain("days=14");
  });

  it("listDetectionRuleEvalStats reports the server's window, not the requested one", async () => {
    stubFetch({ eval_stats: [], days: 30 });
    expect(await listDetectionRuleEvalStats(365)).toEqual({ stats: [], days: 30 });
  });

  // Each row is malformed in exactly ONE way, with every other field valid, so a mutant that breaks one guard is caught by the
  // case for that guard rather than by a fixture that was already failing for a different reason.
  //
  // Built from a valid row rather than written out, which is what keeps that property true as fields are added: a hand-written
  // fixture set drifts the moment one field changes and starts failing for reasons the case name does not claim.
  const validEvalRow = {
    rule_id: "r", evaluations: 1, retryable_misses: 0,
    mean_eval_ns: 1, max_eval_ns: 1, total_eval_ns: 1, last_seen: GOOD_TS,
  };
  const rowWith = (over: Record<string, unknown>) => ({ eval_stats: [{ ...validEvalRow, ...over }], days: 7 });
  // Built by filtering rather than by deleting a computed key, which is the same result without the dynamic-index sink eslint
  // flags: the key is a literal from the table below, but a rule that cannot see that is right to be suspicious of the shape.
  const rowWithout = (field: string) => ({
    eval_stats: [Object.fromEntries(Object.entries(validEvalRow).filter(([k]) => k !== field))],
    days: 7,
  });

  for (const [name, envelope] of [
    ["null eval_stats", { eval_stats: null, days: 7 }],
    ["omitted eval_stats", { days: 7 }],
    ["eval_stats is not an array", { eval_stats: { "0": {} }, days: 7 }],
    ["omitted days", { eval_stats: [] }],
    ["days is not a number", { eval_stats: [], days: "7" }],
    ["days is zero", { eval_stats: [], days: 0 }],
    ["days is fractional", { eval_stats: [], days: 1.5 }],
    ["a row with an empty rule_id", rowWith({ rule_id: "" })],
    ["a row with no rule_id", rowWithout("rule_id")],
    // The floor. Without it a zero row divides by zero somewhere upstream and reads here as a rule that ran for free.
    ["a row with zero evaluations", rowWith({ evaluations: 0 })],
    ["a row missing evaluations", rowWithout("evaluations")],
    ["a row missing retryable_misses", rowWithout("retryable_misses")],
    ["a row missing mean_eval_ns", rowWithout("mean_eval_ns")],
    ["a row missing max_eval_ns", rowWithout("max_eval_ns")],
    ["a row missing total_eval_ns", rowWithout("total_eval_ns")],
    ["a row missing last_seen", rowWithout("last_seen")],
    ["a row whose last_seen is unparseable", rowWith({ last_seen: "not-a-date" })],
    ["a row with a negative timing", rowWith({ mean_eval_ns: -1 })],
    ["a row with a fractional timing", rowWith({ mean_eval_ns: 1.5 })],
    // The two relations. Well-typed and still impossible: the store derives both sides of each from the same rows, so a row
    // breaking one is a response that is not what it claims rather than a rule with unusual numbers.
    ["a row with more undecided attempts than attempts", rowWith({ evaluations: 2, retryable_misses: 3 })],
    ["a row whose mean exceeds its maximum", rowWith({ mean_eval_ns: 900, max_eval_ns: 100 })],
    // The total is a sum over at least one attempt, each at most the maximum, so it cannot be the smaller of the two.
    ["a row whose total is below its maximum", rowWith({ mean_eval_ns: 100, max_eval_ns: 900, total_eval_ns: 100 })],
    ["a row that is null", { eval_stats: [null], days: 7 }],
    ["an empty row", { eval_stats: [{}], days: 7 }],
  ] as [string, unknown][]) {
    it(`listDetectionRuleEvalStats rejects a malformed envelope: ${name}`, async () => {
      stubFetch(envelope);
      await expect(listDetectionRuleEvalStats()).rejects.toThrow(/malformed rule-eval-stats/);
    });
  }

  it("createDetectionExclusion POSTs the body with the CSRF header attached", async () => {
    sessionStorage.setItem("edr_csrf_token", "csrf-123");
    const mock = stubFetch({
      id: 9, rule_id: "suspicious_exec", match_type: "path_glob", value: "*/x/*",
      host_group_id: 0, reason: "r", enabled: true, created_by: "user:1", created_at: "",
    }, 201);
    await createDetectionExclusion({ rule_id: "suspicious_exec", match_type: "path_glob", value: "*/x/*", reason: "r" });
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit & { headers: Record<string, string> }];
    expect(target.toString()).toContain("/api/v1/detection-config/exclusions");
    expect(init.method).toBe("POST");
    const expectedCsrf: Record<string, string> = {};
    attachCsrfHeader(expectedCsrf, "POST");
    expect(init.headers).toMatchObject(expectedCsrf);
  });

  // The reason rides the URL path, which assertSafeAPIPath validates against a strict whitelist. encodeURIComponent leaves
  // `!'()*` literal, and those are NOT in the whitelist, so a reason containing them must be fully percent-encoded or the
  // request throws "unsafe API path". Use a reason with parentheses + bang to pin that the client escapes them.
  it("deleteDetectionExclusion fully percent-encodes the reason so special characters can't trip path validation", async () => {
    const mock = stubFetch({}, 204);
    await deleteDetectionExclusion(5, "resolved (fixed!) & done");
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    const url = target.toString();
    expect(url).toContain("/api/v1/detection-config/exclusions/5");
    // No literal ( ) ! survive into the query string.
    expect(url).not.toMatch(/[!()]/);
    expect(url).toContain("reason=resolved%20%28fixed%21%29%20%26%20done");
    expect(init.method).toBe("DELETE");
  });

  it("upsertDetectionRuleSetting PUTs the body", async () => {
    const mock = stubFetch({
      id: 1, rule_id: "suspicious_exec", host_group_id: 0, mode: "monitor", updated_by: "user:1", updated_at: "",
    });
    await upsertDetectionRuleSetting({ rule_id: "suspicious_exec", mode: "monitor", reason: "noisy" });
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    expect(target.toString()).toContain("/api/v1/detection-config/rule-settings");
    expect(init.method).toBe("PUT");
  });

  it("surfaces a typed error on a 4xx with the {error, message} shape", async () => {
    stubFetch({ error: "detection_config.invalid_input", message: "reason is required" }, 400);
    await expect(
      createDetectionExclusion({ rule_id: "x", match_type: "path_glob", value: "v", reason: "" }),
    ).rejects.toMatchObject({ code: "detection_config.invalid_input", status: 400 });
    // And the thrown value is the typed class, so callers can instanceof-narrow.
    const err = await createDetectionExclusion({ rule_id: "x", match_type: "path_glob", value: "v", reason: "" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DetectionConfigApiError);
  });
});
