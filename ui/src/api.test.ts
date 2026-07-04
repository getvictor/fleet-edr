import { describe, it, expect, vi, afterEach } from "vitest";
import {
  listAlerts,
  getHostHealth,
  getProcessTree,
  createAppControlRule,
  searchProcesses,
  searchEvents,
  setForbiddenHandler,
  setUnauthorizedHandler,
  Unauthorized401Error,
  ReauthRequiredError,
} from "./api";

// listAlerts URL-composition tests. The AlertList component test
// suite mocks api.listAlerts directly via vi.spyOn, so the real
// query-string building inside listAlerts never runs there. So
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

describe("getHostHealth", () => {
  it("requests the per-host health endpoint with the host id encoded", async () => {
    const fetchMock = stubFetch({ overall_status: "unknown", reported_at_ns: 0, components: null });
    await getHostHealth("host/A");
    expect(fetchMock).toHaveBeenCalled();
    const [target] = fetchMock.mock.calls[0] as [URL];
    expect(target.toString()).toContain("/hosts/host%2FA/health");
  });
});

describe("getProcessTree flatten parameter (issue #416)", () => {
  it("omits flatten by default so the response is aggregated", async () => {
    const fetchMock = stubFetch({ roots: [] });
    await getProcessTree("host-a", 1000, 2000);
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("/hosts/host-a/tree?from=1000&to=2000&limit=2000");
    expect(url).not.toContain("flatten");
  });

  it("appends flatten=1 when the caller opts out of aggregation", async () => {
    const fetchMock = stubFetch({ roots: [] });
    await getProcessTree("host-a", 1000, 2000, 2000, true);
    const [target] = fetchMock.mock.calls[0] as [URL];
    expect(target.toString()).toContain("flatten=1");
  });
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

describe("searchProcesses query-string composition", () => {
  // SearchPage and its component tests mock api.searchProcesses via vi.spyOn, so the real URLSearchParams building inside
  // searchProcesses (api.ts) never runs there. These exercise the real function against a stubbed fetch, mirroring the
  // listAlerts composition tests above, so the process-search endpoint's query shape stays covered and pinned.
  it("includes every set filter plus the cursor and omits the unset ones", async () => {
    const fetchMock = stubFetch({ rows: [], total_matched: 0 });
    await searchProcesses(
      { host_id: "host-a", path: "/usr/bin/grep", hash: "abc123", uid: "0", signing: "unsigned", from: "1000", to: "2000" },
      "CURSOR_TOKEN",
    );
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("/search/processes?");
    expect(url).toContain("host_id=host-a");
    expect(url).toContain("path=%2Fusr%2Fbin%2Fgrep");
    expect(url).toContain("hash=abc123");
    expect(url).toContain("uid=0");
    expect(url).toContain("signing=unsigned");
    expect(url).toContain("from=1000");
    expect(url).toContain("to=2000");
    expect(url).toContain("cursor=CURSOR_TOKEN");
  });

  it("emits no query string when the filter is empty and no cursor is given", async () => {
    const fetchMock = stubFetch({ rows: [], total_matched: 0 });
    await searchProcesses({});
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("/search/processes");
    expect(url).not.toContain("?");
  });

  it("omits empty-string filter values so a blank chip does not narrow the query", async () => {
    const fetchMock = stubFetch({ rows: [], total_matched: 0 });
    await searchProcesses({ path: "", uid: "0" });
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).not.toContain("path=");
    expect(url).toContain("uid=0");
  });
});

describe("searchEvents query-string composition", () => {
  // The EventSearch component mocks api.searchEvents via vi.spyOn, so the real path/param building never runs there. These pin the
  // two endpoints' shapes: connections carries the artifact as remote_address, dns as query_name, both under /search/<mode>.
  it("hits the connections endpoint carrying the remote address, host, window, and cursor", async () => {
    const fetchMock = stubFetch({ events: [], total_matched: 0 });
    await searchEvents("connections", { value: "1.2.3.4", host_id: "host-a", from: "1000", to: "2000" }, "CURSOR");
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("/search/connections?");
    expect(url).toContain("remote_address=1.2.3.4");
    expect(url).toContain("host_id=host-a");
    expect(url).toContain("from=1000");
    expect(url).toContain("to=2000");
    expect(url).toContain("cursor=CURSOR");
    expect(url).not.toContain("query_name=");
  });

  it("hits the dns endpoint carrying the domain as query_name", async () => {
    const fetchMock = stubFetch({ events: [], total_matched: 0 });
    await searchEvents("dns", { value: "evil.example.com" });
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("/search/dns?query_name=evil.example.com");
    expect(url).not.toContain("remote_address=");
  });

  it("omits host, window, and cursor when only the artifact value is given", async () => {
    const fetchMock = stubFetch({ events: [], total_matched: 0 });
    await searchEvents("connections", { value: "1.2.3.4" });
    const [target] = fetchMock.mock.calls[0] as [URL];
    const url = target.toString();
    expect(url).toContain("remote_address=1.2.3.4");
    expect(url).not.toContain("host_id=");
    expect(url).not.toContain("cursor=");
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

describe("unauthorized handler signalling", () => {
  afterEach(() => { setUnauthorizedHandler(null); });

  // spec:web-ui/authenticated-entry-to-the-application/mid-session-expiry-returns-the-operator-to-login
  it("fires on a 401 from a safe-method fetch so the app can redirect to login", async () => {
    stubFetch(null, 401);
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    await expect(listAlerts()).rejects.toBeInstanceOf(Unauthorized401Error);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  // spec:web-ui/authenticated-entry-to-the-application/mid-session-expiry-returns-the-operator-to-login
  it("fires on a 401 from an unsafe-method (mutation) fetch too", async () => {
    // The app-control mutation endpoint is a second 401 throw site; both funnel through raiseUnauthorized so a
    // session that lapses mid-mutation redirects exactly like one that lapses on a read.
    stubFetch(null, 401);
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    await expect(createAppControlRule(1, { rule_type: "team_id", identifier: "ABCDE12345", reason: "test" }))
      .rejects.toBeInstanceOf(Unauthorized401Error);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("does not fire once cleared with null", async () => {
    stubFetch(null, 401);
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    setUnauthorizedHandler(null);
    await expect(listAlerts()).rejects.toBeInstanceOf(Unauthorized401Error);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});
