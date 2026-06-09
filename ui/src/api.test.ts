import { describe, it, expect, vi, afterEach } from "vitest";
import { listAlerts, setForbiddenHandler, ReauthRequiredError } from "./api";

// listAlerts URL-composition tests. The AlertList component test
// suite mocks api.listAlerts directly via vi.spyOn, so the real
// query-string building inside listAlerts never runs there - and
// the new ?source= branch added in step 9 was the only line in
// api.ts not covered by other tests. These tests exercise the
// real listAlerts against a stubbed global fetch so the source
// branch (and the other optional params it already shipped with)
// stay covered going forward.

interface FakeResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: { get(name: string): string | null };
  clone(): FakeResponse;
  json(): Promise<unknown>;
}

// stubFetch installs a fake global fetch returning a single response. headers maps response
// header names (case-insensitive, matching the real Headers.get contract) so tests can drive
// the X-Edr-Authz-Reason gate on the 403 path.
function stubFetch(body: unknown, status = 200, headers: Record<string, string> = {}): ReturnType<typeof vi.fn> {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  const fake: FakeResponse = {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: { get: (name: string): string | null => lower[name.toLowerCase()] ?? null },
    clone(): FakeResponse {
      return fake;
    },
    json(): Promise<unknown> {
      return Promise.resolve(body);
    },
  };
  const mock = vi.fn().mockResolvedValue(fake);
  vi.stubGlobal("fetch", mock);
  return mock;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("listAlerts query-string composition", () => {
  it("forwards the source filter as a ?source=<value> query param", async () => {
    const fetchMock = stubFetch([]);
    await listAlerts({ source: "application_control" });
    expect(fetchMock).toHaveBeenCalled();
    // fetchJSON builds the request URL through the WHATWG URL
    // constructor (api.ts line ~175) for taint sanitisation, so the
    // first argument is a URL instance, not a string. Stringify it
    // explicitly so toContain works on the rendered href.
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("/alerts?source=application_control");
  });

  it("includes every set filter and omits the unset ones", async () => {
    const fetchMock = stubFetch([]);
    await listAlerts({
      host_id: "host-a",
      status: "open",
      severity: "high",
      source: "detection",
      process_id: 42,
      limit: 25,
    });
    // fetchJSON builds the request URL through the WHATWG URL
    // constructor (api.ts line ~175) for taint sanitisation, so the
    // first argument is a URL instance, not a string. Stringify it
    // explicitly so toContain works on the rendered href.
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    // URLSearchParams uses URL-encoded ampersands; assert on each
    // key/value pair independently so the order of params doesn't
    // matter (URLSearchParams.toString preserves insertion order
    // but the contract we care about is "every set key arrives,
    // unset keys don't").
    expect(url).toContain("host_id=host-a");
    expect(url).toContain("status=open");
    expect(url).toContain("severity=high");
    expect(url).toContain("source=detection");
    expect(url).toContain("process_id=42");
    expect(url).toContain("limit=25");
  });

  it("emits no query string when no filters are passed", async () => {
    const fetchMock = stubFetch([]);
    await listAlerts();
    // fetchJSON builds the request URL through the WHATWG URL
    // constructor (api.ts line ~175) for taint sanitisation, so the
    // first argument is a URL instance, not a string. Stringify it
    // explicitly so toContain works on the rendered href.
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("/alerts");
    expect(url).not.toContain("?");
  });

  it("does not emit source= when source is the empty string", async () => {
    const fetchMock = stubFetch([]);
    await listAlerts({ source: "" });
    // fetchJSON builds the request URL through the WHATWG URL
    // constructor (api.ts line ~175) for taint sanitisation, so the
    // first argument is a URL instance, not a string. Stringify it
    // explicitly so toContain works on the rendered href.
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).not.toContain("source=");
  });
});

describe("forbidden handler signalling", () => {
  afterEach(() => { setForbiddenHandler(null); });

  // spec:web-ui/authorization-denials-degrade-gracefully/mid-session-revocation-degrades-and-refetches
  it("fires on an authz 403 (carrying the chokepoint reason header) so the UI can refresh permissions", async () => {
    stubFetch({ error: "no_matching_rule" }, 403, { "X-Edr-Authz-Reason": "no_matching_rule" });
    const onForbidden = vi.fn();
    setForbiddenHandler(onForbidden);
    await expect(listAlerts()).rejects.toThrow(/API error: 403/);
    expect(onForbidden).toHaveBeenCalledTimes(1);
  });

  it("does NOT fire on a 403 without the authz reason header (e.g. a CSRF failure)", async () => {
    // CSRF and other non-authz 403s go through WriteCookieAuthFailure and carry no authz header,
    // so they must not trigger a spurious /api/session permission refetch.
    stubFetch({ error: "csrf_mismatch" }, 403);
    const onForbidden = vi.fn();
    setForbiddenHandler(onForbidden);
    await expect(listAlerts()).rejects.toThrow(/API error: 403/);
    expect(onForbidden).not.toHaveBeenCalled();
  });

  it("does NOT fire on a reauth-required 403 (that has its own retry flow)", async () => {
    stubFetch({ error: "reauth_required", challenge: { auth_method: "oidc", reauth_url: "/api/auth/login" } }, 403);
    const onForbidden = vi.fn();
    setForbiddenHandler(onForbidden);
    await expect(listAlerts()).rejects.toBeInstanceOf(ReauthRequiredError);
    expect(onForbidden).not.toHaveBeenCalled();
  });

  it("does NOT fire on a 401 (session expiry has its own path)", async () => {
    stubFetch(null, 401);
    const onForbidden = vi.fn();
    setForbiddenHandler(onForbidden);
    await expect(listAlerts()).rejects.toBeTruthy();
    expect(onForbidden).not.toHaveBeenCalled();
  });
});
