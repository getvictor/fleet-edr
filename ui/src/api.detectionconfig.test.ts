import { describe, it, expect, vi, afterEach } from "vitest";
import {
  listDetectionExclusions,
  listDetectionRuleSettings,
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

  // The component tests mock this client wholesale, so the query serialisation and the null coalescing below have no other
  // coverage. Both have a history here: a null envelope crashed the exclusions page once already (see above).
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
  ] as [string, unknown][]) {
    it(`listDetectionRuleMatchCounts rejects a malformed envelope: ${name}`, async () => {
      stubFetch(envelope);
      await expect(listDetectionRuleMatchCounts()).rejects.toThrow(/malformed rule-match-counts/);
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
