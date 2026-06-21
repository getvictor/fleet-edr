import { describe, it, expect, vi, afterEach } from "vitest";
import {
  listServiceAccounts,
  createServiceAccount,
  rotateServiceAccount,
  revokeServiceAccount,
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

describe("service-account API client", () => {
  it("listServiceAccounts GETs the collection and unwraps the envelope", async () => {
    const mock = stubFetch({
      service_accounts: [{ id: 1, client_id: "sa_a", name: "a", role: "analyst", status: "active", created_at: "", expires_at: "" }],
    });
    const out = await listServiceAccounts();
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/service-accounts");
    expect(init?.method ?? "GET").toBe("GET");
    expect(out).toHaveLength(1);
  });

  it("listServiceAccounts tolerates a null envelope", async () => {
    stubFetch({ service_accounts: null });
    expect(await listServiceAccounts()).toEqual([]);
  });

  it("createServiceAccount POSTs the body with the CSRF header attached", async () => {
    sessionStorage.setItem("edr_csrf_token", "csrf-123");
    const mock = stubFetch({
      id: 2, client_id: "sa_b", name: "b", role: "analyst", status: "active", created_at: "", expires_at: "", secret: "edrsa_x",
    });
    await createServiceAccount({ name: "b", role: "analyst", expires_in_days: 30 });
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit & { headers: Record<string, string> }];
    expect(target.toString()).toContain("/api/settings/service-accounts");
    expect(init.method).toBe("POST");
    const expectedCsrf: Record<string, string> = {};
    attachCsrfHeader(expectedCsrf, "POST");
    expect(init.headers).toMatchObject(expectedCsrf);
    expect(JSON.parse(init.body as string)).toEqual({ name: "b", role: "analyst", expires_in_days: 30 });
  });

  it("rotateServiceAccount POSTs to the rotate sub-path", async () => {
    const mock = stubFetch({ secret: "edrsa_rot" });
    const res = await rotateServiceAccount(7);
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    expect(target.toString()).toContain("/api/settings/service-accounts/7/rotate");
    expect(init.method).toBe("POST");
    expect(res).toEqual({ secret: "edrsa_rot" });
  });

  it("revokeServiceAccount DELETEs the resource", async () => {
    const mock = stubFetch({ status: "revoked" });
    await revokeServiceAccount(9);
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    expect(target.toString()).toContain("/api/settings/service-accounts/9");
    expect(init.method).toBe("DELETE");
  });
});
