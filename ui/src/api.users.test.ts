import { describe, it, expect, vi, afterEach } from "vitest";
import { createUser, listUsers, setUserRole, setUserStatus, attachCsrfHeader } from "./api";

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

describe("user-management API client", () => {
  it("listUsers GETs the collection and unwraps the envelope", async () => {
    const mock = stubFetch({
      users: [{ id: 1, email: "a@x.com", role: "analyst", roles: ["analyst"], status: "active", is_breakglass: false }],
    });
    const out = await listUsers();
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit | undefined];
    expect(target.toString()).toContain("/api/settings/users");
    expect(init?.method ?? "GET").toBe("GET");
    expect(out).toHaveLength(1);
  });

  it("listUsers tolerates a null envelope", async () => {
    stubFetch({ users: null });
    expect(await listUsers()).toEqual([]);
  });

  it("setUserRole PUTs the role with the CSRF header attached", async () => {
    sessionStorage.setItem("edr_csrf_token", "csrf-xyz");
    const mock = stubFetch({ id: 7, email: "b@x.com", role: "senior_analyst", roles: ["senior_analyst"], status: "active", is_breakglass: false });
    await setUserRole(7, "senior_analyst");
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit & { headers: Record<string, string> }];
    expect(target.toString()).toContain("/api/settings/users/7/role");
    expect(init.method).toBe("PUT");
    const expectedCsrf: Record<string, string> = {};
    attachCsrfHeader(expectedCsrf, "PUT");
    expect(init.headers).toMatchObject(expectedCsrf);
    expect(JSON.parse(init.body as string)).toEqual({ role: "senior_analyst" });
  });

  it("setUserStatus PUTs the status to the status sub-path", async () => {
    const mock = stubFetch({ id: 9, email: "c@x.com", role: "analyst", roles: ["analyst"], status: "disabled", is_breakglass: false });
    await setUserStatus(9, "disabled");
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit];
    expect(target.toString()).toContain("/api/settings/users/9/status");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({ status: "disabled" });
  });

  it("createUser POSTs the email + role and returns the provisioned user", async () => {
    sessionStorage.setItem("edr_csrf_token", "csrf-xyz");
    const mock = stubFetch(
      { id: 11, email: "staged@x.com", role: "senior_analyst", roles: ["senior_analyst"], status: "provisioned", is_breakglass: false },
      201,
    );
    const out = await createUser("Staged@X.com", "senior_analyst");
    const [target, init] = mock.mock.calls[0] as [URL, RequestInit & { headers: Record<string, string> }];
    expect(target.toString()).toContain("/api/settings/users");
    expect(init.method).toBe("POST");
    const expectedCsrf: Record<string, string> = {};
    attachCsrfHeader(expectedCsrf, "POST");
    expect(init.headers).toMatchObject(expectedCsrf);
    expect(JSON.parse(init.body as string)).toEqual({ email: "Staged@X.com", role: "senior_analyst" });
    expect(out.status).toBe("provisioned");
  });
});
