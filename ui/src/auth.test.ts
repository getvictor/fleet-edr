import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  BreakglassError,
  oidcLoginUrl,
  breakglassBeginSetup,
  breakglassFinishSetup,
  breakglassBeginLogin,
  breakglassFinishLogin,
  reauthBreakglass,
  reauthOIDC,
} from "./auth";
import { setUnauthorizedHandler } from "./api";

// The auth.ts surface covers the pre-auth break-glass + OIDC redirect helpers. These tests pin the
// observable contract of each helper: URL shape, fetch wire shape (method + headers + body + credentials), error mapping
// (BreakglassError carries the X-Edr-Auth-Reason header verbatim or the http_<status> fallback), and the post-call
// navigation side effects (reauthOIDC's globalThis.location.assign). The WebAuthn-ceremony calls into
// @simplewebauthn/browser are stubbed via vi.mock so the tests don't depend on a real navigator.credentials surface.
//
// Test conventions match ui/src/api.test.ts:
//   stubFetch builds a typed fake Response so the helper's res.json() / res.headers.get() / res.status calls all work.
//   afterEach restores all mocks so test order doesn't matter.
//   One describe per exported symbol; one it per documented branch.

vi.mock("@simplewebauthn/browser", () => ({
  startRegistration: vi.fn(),
  startAuthentication: vi.fn(),
}));

// Re-import the stubbed module so individual tests can assert on the spy calls.
import {
  startRegistration as mockedStartRegistration,
  startAuthentication as mockedStartAuthentication,
} from "@simplewebauthn/browser";

interface FakeResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

function stubFetch(
  body: unknown,
  status = 200,
  reason?: string,
  contentType: string | null = "application/json",
): ReturnType<typeof vi.fn> {
  const headerMap = new Map<string, string>();
  if (reason !== undefined) headerMap.set("X-Edr-Auth-Reason", reason);
  if (contentType !== null) headerMap.set("Content-Type", contentType);
  const fake: FakeResponse = {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: {
      get: (n: string) => headerMap.get(n) ?? null,
    },
    json: () => Promise.resolve(body),
  };
  return vi.fn().mockResolvedValue(fake);
}

afterEach(() => {
  // restoreAllMocks resets vi.spyOn spies; clearAllMocks resets the call history on vi.fn() / vi.mock() module mocks
  // (without it, `toHaveBeenCalled` assertions accumulate across tests and a "should not have been called" assertion
  // false-positives on a prior test's call).
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  setUnauthorizedHandler(null);
});

describe("BreakglassError", () => {
  it("stores status + reason and carries the canonical name", () => {
    const e = new BreakglassError(429, "rate_limited");
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("BreakglassError");
    expect(e.status).toBe(429);
    expect(e.reason).toBe("rate_limited");
    expect(e.message).toContain("rate_limited");
    expect(e.message).toContain("429");
  });
});

describe("oidcLoginUrl", () => {
  it("returns the bare /api/auth/login when next is undefined", () => {
    expect(oidcLoginUrl()).toBe("/api/auth/login");
  });

  it("returns the bare URL when next is the empty string", () => {
    expect(oidcLoginUrl("")).toBe("/api/auth/login");
  });

  it("appends a same-origin path next=", () => {
    expect(oidcLoginUrl("/ui/alerts")).toBe("/api/auth/login?next=%2Fui%2Falerts");
  });

  it("encodes special characters in the next path", () => {
    expect(oidcLoginUrl("/ui/hosts/abc?foo=bar")).toBe("/api/auth/login?next=%2Fui%2Fhosts%2Fabc%3Ffoo%3Dbar");
  });

  it("drops a next that doesn't start with /", () => {
    expect(oidcLoginUrl("ui/alerts")).toBe("/api/auth/login");
  });

  it("drops a protocol-relative // next (open-redirect defence)", () => {
    expect(oidcLoginUrl("//evil.example.com")).toBe("/api/auth/login");
  });

  it("drops a next longer than the 256-char cap", () => {
    const long = "/ui/" + "a".repeat(260);
    expect(oidcLoginUrl(long)).toBe("/api/auth/login");
  });

  it("drops a next containing characters outside the allowlist", () => {
    // Spaces (encoded or otherwise) aren't in the regex; the helper rejects them.
    expect(oidcLoginUrl("/ui/alerts page")).toBe("/api/auth/login");
  });
});

describe("breakglassBeginSetup", () => {
  it("POSTs to the challenge endpoint with the token and runs startRegistration", async () => {
    const publicKey = { challenge: "c", rp: { id: "x", name: "x" }, user: { id: "u", name: "u", displayName: "u" } };
    const fetchSpy = stubFetch({ publicKey });
    vi.stubGlobal("fetch", fetchSpy);
    vi.mocked(mockedStartRegistration).mockResolvedValue({ id: "att-1" } as unknown as never);

    const result = await breakglassBeginSetup("redeem-tok");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const req = fetchSpy.mock.calls[0]?.[1] as RequestInit;
    expect(req.method).toBe("POST");
    expect(req.credentials).toBe("include");
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain("/admin/break-glass/setup/challenge?token=redeem-tok");
    expect(mockedStartRegistration).toHaveBeenCalledWith({ optionsJSON: publicKey });
    expect(result).toEqual({ id: "att-1" });
  });

  it("URL-encodes the redemption token", async () => {
    const fetchSpy = stubFetch({ publicKey: {} });
    vi.stubGlobal("fetch", fetchSpy);
    vi.mocked(mockedStartRegistration).mockResolvedValue({} as unknown as never);
    await breakglassBeginSetup("a b/c?d");
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain("token=a%20b%2Fc%3Fd");
  });

  it("throws BreakglassError carrying the wire reason on 4xx", async () => {
    const fetchSpy = stubFetch({}, 410, "token_gone");
    vi.stubGlobal("fetch", fetchSpy);
    await expect(breakglassBeginSetup("expired")).rejects.toMatchObject({
      name: "BreakglassError",
      status: 410,
      reason: "token_gone",
    });
  });

  it("falls back to http_<status> when X-Edr-Auth-Reason is missing", async () => {
    const fetchSpy = stubFetch({}, 500);
    vi.stubGlobal("fetch", fetchSpy);
    await expect(breakglassBeginSetup("t")).rejects.toMatchObject({ reason: "http_500" });
  });
});

describe("breakglassFinishSetup", () => {
  it("POSTs the password + credentialName + attestation as JSON", async () => {
    const fetchSpy = stubFetch({ redirect: "/ui/" });
    vi.stubGlobal("fetch", fetchSpy);
    const att = { id: "att" };
    const result = await breakglassFinishSetup("tok", "secret", "Yubikey", att);
    expect(result).toEqual({ redirect: "/ui/" });
    const req = fetchSpy.mock.calls[0]?.[1] as RequestInit;
    expect(req.method).toBe("POST");
    expect(JSON.parse(req.body as string)).toEqual({
      password: "secret",
      credential_name: "Yubikey",
      attestation: att,
    });
  });

  it("returns undefined for a 204 No Content response", async () => {
    const fetchSpy = stubFetch(null, 204, undefined, null);
    vi.stubGlobal("fetch", fetchSpy);
    const result = await breakglassFinishSetup("t", "p", "n", {});
    expect(result).toBeUndefined();
  });
});

describe("breakglassBeginLogin", () => {
  it("POSTs the email and forwards the publicKey to startAuthentication", async () => {
    const publicKey = { challenge: "c" };
    const fetchSpy = stubFetch({ publicKey });
    vi.stubGlobal("fetch", fetchSpy);
    vi.mocked(mockedStartAuthentication).mockResolvedValue({ id: "assert" } as unknown as never);

    const result = await breakglassBeginLogin("ops@example.com");

    const req = fetchSpy.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(req.body as string)).toEqual({ email: "ops@example.com" });
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain("/admin/break-glass/challenge");
    expect(mockedStartAuthentication).toHaveBeenCalledWith({ optionsJSON: publicKey });
    expect(result).toEqual({ id: "assert" });
  });
});

describe("breakglassFinishLogin", () => {
  it("POSTs email + password + assertion and returns the redirect", async () => {
    const fetchSpy = stubFetch({ redirect: "/ui/alerts" });
    vi.stubGlobal("fetch", fetchSpy);
    const assertion = { id: "asrt" };
    const result = await breakglassFinishLogin("ops@example.com", "pw", assertion);
    expect(result).toEqual({ redirect: "/ui/alerts" });
    const req = fetchSpy.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(req.body as string)).toEqual({
      email: "ops@example.com",
      password: "pw",
      assertion,
    });
  });

  it("surfaces the server reason on 401", async () => {
    const fetchSpy = stubFetch({}, 401, "invalid_credentials");
    vi.stubGlobal("fetch", fetchSpy);
    await expect(breakglassFinishLogin("o", "p", {})).rejects.toMatchObject({
      status: 401,
      reason: "invalid_credentials",
    });
  });

  // spec:web-ui/authenticated-entry-to-the-application/mid-session-expiry-returns-the-operator-to-login
  it("does NOT fire the global unauthorized handler on a pre-auth break-glass 401", async () => {
    // The pre-auth /admin/break-glass/* surface returns 401 on a wrong credential, not an expired session, so it must
    // not trigger the login redirect (the operator is already on the sign-in surface).
    const fetchSpy = stubFetch({}, 401, "invalid_credentials");
    vi.stubGlobal("fetch", fetchSpy);
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    await expect(breakglassFinishLogin("o", "p", {})).rejects.toBeInstanceOf(BreakglassError);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

describe("reauthBreakglass", () => {
  it("runs challenge → startAuthentication → submit and resolves on 2xx", async () => {
    const publicKey = { challenge: "c" };
    // Two sequential fetches: first the challenge endpoint, then the reauth POST. mockResolvedValueOnce stacks them.
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: "",
        headers: { get: (n: string) => (n === "Content-Type" ? "application/json" : null) },
        json: () => Promise.resolve({ publicKey }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: "",
        headers: { get: (n: string) => (n === "Content-Type" ? "application/json" : null) },
        json: () => Promise.resolve({ ok: true }),
      });
    vi.stubGlobal("fetch", fetchSpy);
    vi.mocked(mockedStartAuthentication).mockResolvedValue({ id: "as" } as unknown as never);

    await expect(reauthBreakglass("pw")).resolves.toBeUndefined();

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain("/api/auth/reauth/challenge");
    expect(String(fetchSpy.mock.calls[1]?.[0])).toContain("/api/auth/reauth");
    const body = JSON.parse((fetchSpy.mock.calls[1]?.[1] as RequestInit).body as string) as {
      password: string;
      assertion: { id: string };
    };
    expect(body).toEqual({ password: "pw", assertion: { id: "as" } });
  });

  it("rejects with BreakglassError if the challenge endpoint returns 429", async () => {
    const fetchSpy = stubFetch({}, 429, "rate_limited");
    vi.stubGlobal("fetch", fetchSpy);
    await expect(reauthBreakglass("pw")).rejects.toMatchObject({
      name: "BreakglassError",
      status: 429,
      reason: "rate_limited",
    });
    // Should NOT have run startAuthentication when the challenge call itself rejected.
    expect(mockedStartAuthentication).not.toHaveBeenCalled();
  });

  // spec:web-ui/authenticated-entry-to-the-application/mid-session-expiry-returns-the-operator-to-login
  it("fires the global unauthorized handler on a middleware 401 (no X-Edr-Auth-Reason) from the reauth path", async () => {
    // A session that lapses mid-reauth is rejected by the Session middleware, which short-circuits via WriteCookieAuthFailure
    // and never sets X-Edr-Auth-Reason. The absent header is the discriminator: signal the redirect-to-login handler (so the app
    // flips to anon) AND still reject with BreakglassError. stubFetch with no reason models the headerless middleware response.
    const fetchSpy = stubFetch({}, 401);
    vi.stubGlobal("fetch", fetchSpy);
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    await expect(reauthBreakglass("pw")).rejects.toBeInstanceOf(BreakglassError);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
    expect(mockedStartAuthentication).not.toHaveBeenCalled();
  });

  it("does NOT fire the unauthorized handler on a 401 invalid_credentials (wrong password, session still valid)", async () => {
    // The reauth handler returns 401 with X-Edr-Auth-Reason: invalid_credentials on a wrong password/assertion. The session is
    // still valid, so the operator must be able to retry in the modal: the present header means do NOT flip to anon / redirect.
    // It still rejects with BreakglassError so the modal renders its inline "wrong credentials" error.
    const fetchSpy = stubFetch({}, 401, "invalid_credentials");
    vi.stubGlobal("fetch", fetchSpy);
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    await expect(reauthBreakglass("pw")).rejects.toMatchObject({
      name: "BreakglassError",
      status: 401,
      reason: "invalid_credentials",
    });
    expect(onUnauthorized).not.toHaveBeenCalled();
    expect(mockedStartAuthentication).not.toHaveBeenCalled();
  });
});

// stubLocation replaces window.location with a synthetic object exposing only the fields reauthOIDC reads. We use
// vi.stubGlobal rather than vi.spyOn(location, "assign") because jsdom's location.assign is non-configurable and spyOn
// throws "Cannot redefine property: assign" (the CodeRabbit + Gemini #278 suggestion was tested and produces that
// error). Replacing the whole location object DOES work in this jsdom because window.location itself is configurable;
// afterEach -> vi.unstubAllGlobals() restores the original on teardown.
function stubLocation(pathname: string, search = "", hash = ""): ReturnType<typeof vi.fn> {
  const assignSpy = vi.fn();
  vi.stubGlobal("location", {
    origin: "https://edr.test",
    pathname,
    search,
    hash,
    assign: assignSpy,
  });
  return assignSpy;
}

describe("reauthOIDC", () => {
  it("redirects to the baseURL with next=<current path> when on a same-origin path", () => {
    const assignSpy = stubLocation("/ui/alerts/42", "?status=open");
    reauthOIDC("/api/auth/login?reauth=1");
    expect(assignSpy).toHaveBeenCalledTimes(1);
    const url = String(assignSpy.mock.calls[0]?.[0]);
    expect(url).toContain("/api/auth/login?reauth=1&next=");
    expect(url).toContain(encodeURIComponent("/ui/alerts/42?status=open"));
  });

  it("falls back to the default /api/auth/login?reauth=1 when baseURL is off-shape", () => {
    const assignSpy = stubLocation("/ui/");
    // Off-shape baseURL: doesn't start with /, would otherwise let a hostile server steer the redirect.
    reauthOIDC("https://evil.example.com/login");
    expect(String(assignSpy.mock.calls[0]?.[0])).toContain("/api/auth/login?reauth=1");
    expect(String(assignSpy.mock.calls[0]?.[0])).not.toContain("evil.example.com");
  });

  it("omits next= when the current path itself fails the allowlist", () => {
    // Pathname with a character outside the regex's allowlist, which exercises the safeNext === "" branch.
    const assignSpy = stubLocation("/ui/with space");
    reauthOIDC("/api/auth/login?reauth=1");
    expect(String(assignSpy.mock.calls[0]?.[0])).toBe("/api/auth/login?reauth=1");
  });
});

describe("requestJSON behaviour via the wrappers", () => {
  // requestJSON itself is internal; the wrapped exports exercise its behaviour. The remaining branches not covered above:
  //   - non-JSON 2xx body (Content-Type != application/json) returns undefined to typed callers.
  //   - 4xx without X-Edr-Auth-Reason falls back to http_<status>.
  //   - Content-Length: 0 short-circuits the JSON parse.
  beforeEach(() => {
    vi.mocked(mockedStartAuthentication).mockResolvedValue({ id: "a" } as unknown as never);
    vi.mocked(mockedStartRegistration).mockResolvedValue({ id: "r" } as unknown as never);
  });

  it("returns undefined for a 2xx with a non-JSON Content-Type", async () => {
    // breakglassFinishSetup's redirect type is { redirect: string }; the helper sees an empty body and resolves undefined
    // rather than throwing on the json() parse of the empty body.
    const fetchSpy = stubFetch(null, 200, undefined, "text/plain");
    vi.stubGlobal("fetch", fetchSpy);
    const result = await breakglassFinishSetup("t", "p", "n", {});
    expect(result).toBeUndefined();
  });

  it("returns undefined when Content-Length is 0 even with a JSON Content-Type", async () => {
    const headerMap = new Map<string, string>();
    headerMap.set("Content-Type", "application/json");
    headerMap.set("Content-Length", "0");
    const fake = {
      ok: true,
      status: 200,
      statusText: "",
      headers: { get: (n: string) => headerMap.get(n) ?? null },
      json: () => Promise.reject(new Error("should not be called")),
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(fake));
    const result = await breakglassFinishSetup("t", "p", "n", {});
    expect(result).toBeUndefined();
  });
});
