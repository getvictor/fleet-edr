import { describe, it, expect, vi, afterEach } from "vitest";
import { getSSOConfig, updateSSOConfig, testSSOConnection, attachCsrfHeader } from "./api";

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

describe("SSO config API client", () => {
  it("getSSOConfig GETs /api/settings/sso", async () => {
    const mock = stubFetch({ configured: false });
    await getSSOConfig();
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/sso");
    expect(init?.method ?? "GET").toBe("GET");
  });

  it("updateSSOConfig PUTs the body with the CSRF header attached", async () => {
    sessionStorage.setItem("edr_csrf_token", "csrf-token-123");
    const mock = stubFetch({ configured: true });
    await updateSSOConfig({
      issuer: "https://idp", client_id: "cid", external_url: "https://e",
      scopes: ["openid"], jit_enabled: true, default_role: "analyst",
    });
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit & { headers: Record<string, string> }];
    expect(target.toString()).toContain("/api/settings/sso");
    expect(init.method).toBe("PUT");
    // Derive the expected CSRF header via the canonical helper rather than hardcoding the header name.
    const expectedCsrf: Record<string, string> = {};
    attachCsrfHeader(expectedCsrf, "PUT");
    expect(Object.keys(expectedCsrf).length).toBeGreaterThan(0);
    expect(init.headers).toMatchObject(expectedCsrf);
    expect(JSON.parse(init.body as string)).toMatchObject({ issuer: "https://idp", default_role: "analyst" });
  });

  it("testSSOConnection POSTs the issuer", async () => {
    const mock = stubFetch({ ok: true });
    const res = await testSSOConnection("https://idp.example.com");
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    expect(target.toString()).toContain("/api/settings/sso/test-connection");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ issuer: "https://idp.example.com" });
    expect(res).toEqual({ ok: true });
  });
});
