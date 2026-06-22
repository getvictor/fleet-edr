import { describe, it, expect, vi, afterEach } from "vitest";
import {
  listDetectionExclusions,
  listDetectionRuleSettings,
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

  it("deleteDetectionExclusion carries the reason as a query parameter on a DELETE", async () => {
    const mock = stubFetch({}, 204);
    await deleteDetectionExclusion(5, "resolved & done");
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    const url = target.toString();
    expect(url).toContain("/api/v1/detection-config/exclusions/5");
    expect(url).toContain(`reason=${encodeURIComponent("resolved & done")}`);
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
