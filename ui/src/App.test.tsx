import { describe, it, expect, vi, afterEach } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router";
import { AuthedApp } from "./App";
import * as api from "./api";
import { setUnauthorizedHandler, setForbiddenHandler } from "./api";
import { PermissionAction } from "./permissions-core";

// AuthedApp gates the app on a live session. On mount it probes GET /api/session; on a 401 there it
// renders the login page. The regression this suite pins: a session that lapses MID-USE (a background
// /api/* fetch returns 401 after the mount probe already succeeded) must also return the operator to
// login, via the global unauthorized handler AuthedApp registers. Before the fix the 401 was caught
// inline by each component and the operator was stranded on a dead page.

interface FakeResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: { get(name: string): string | null };
  clone(): FakeResponse;
  json(): Promise<unknown>;
}

function makeResponse(body: unknown, status: number): FakeResponse {
  const res: FakeResponse = {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: { get: (): string | null => null },
    clone(): FakeResponse {
      return res;
    },
    json(): Promise<unknown> {
      return Promise.resolve(body);
    },
  };
  return res;
}

const authedSession = {
  user: { id: 1, email: "operator@example.com" },
  csrf_token: "csrf-abc",
  auth_method: "oidc",
  permissions: [],
};

// stubSessionThen401 routes GET /api/session to a 200 authed session (so AuthedApp's mount probe
// succeeds and renders the home view) and every other /api/* call to 401 (so the home view's first
// background fetch trips session expiry). fetchJSON calls fetch with a URL instance, so the first arg
// is stringified to read the path.
function stubSessionThen401(): ReturnType<typeof vi.fn> {
  const mock = vi.fn((input: unknown): Promise<FakeResponse> => {
    const url = String(input);
    if (url.includes("/api/session")) return Promise.resolve(makeResponse(authedSession, 200));
    return Promise.resolve(makeResponse(null, 401));
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

function renderAuthedApp() {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route path="/login" element={<div>LOGIN PAGE</div>} />
        <Route path="/*" element={<AuthedApp />} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => {
  setUnauthorizedHandler(null);
  setForbiddenHandler(null);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// stubAuthedSession routes GET /api/session to an authed session carrying the given
// permission set, and every list endpoint to an empty 200 result so the home redirect's
// destination page mounts to its empty state instead of tripping the 401 handler.
function stubAuthedSession(permissions: string[]): void {
  const mock = vi.fn((input: unknown): Promise<FakeResponse> => {
    const url = String(input);
    if (url.includes("/api/session")) return Promise.resolve(makeResponse({ ...authedSession, permissions }, 200));
    return Promise.resolve(makeResponse([], 200));
  });
  vi.stubGlobal("fetch", mock);
}

describe("home view routing", () => {
  // spec:web-ui/alert-list-is-the-home-view/root-routes-to-the-alert-list
  it("lands on the alert list at the root for an operator with alert.read", async () => {
    stubAuthedSession([PermissionAction.AlertRead, PermissionAction.HostRead]);
    renderAuthedApp();
    expect(await screen.findByText("No alerts found.")).toBeInTheDocument();
  });

  // spec:web-ui/alert-list-is-the-home-view/operator-without-alert-read-lands-on-their-first-permitted-surface
  it("lands on the hosts page at the root for an operator without alert.read", async () => {
    stubAuthedSession([PermissionAction.HostRead]);
    renderAuthedApp();
    expect(await screen.findByText("No hosts reporting yet.")).toBeInTheDocument();
  });
});

describe("AuthedApp account menu", () => {
  async function openAccountMenu() {
    fireEvent.click(await screen.findByRole("button", { name: "Account menu" }));
  }

  it("names the role the session probe returns", async () => {
    vi.spyOn(api, "currentSession").mockResolvedValue({ ...authedSession, roles: ["auditor"] });
    renderAuthedApp();
    await openAccountMenu();
    expect(screen.getByText("Role: Auditor")).toBeVisible();
  });

  // spec:web-ui/the-account-menu-names-the-session-s-role-and-sign-in-method/a-session-whose-roles-are-not-reported-names-no-role
  it("names no role when the server does not send the session's roles", async () => {
    vi.spyOn(api, "currentSession").mockResolvedValue(authedSession);
    renderAuthedApp();
    await openAccountMenu();
    expect(screen.getByText("operator@example.com")).toBeVisible();
    expect(screen.queryByText(/Role:/)).not.toBeInTheDocument();
  });

  // spec:web-ui/the-account-menu-names-the-session-s-role-and-sign-in-method/the-named-role-follows-a-refetched-session
  it("names the new role when a denial refetches the session", async () => {
    vi.spyOn(api, "currentSession")
      .mockResolvedValueOnce({ ...authedSession, roles: ["senior_analyst"] })
      .mockResolvedValueOnce({ ...authedSession, roles: ["analyst"] });
    const setForbidden = vi.spyOn(api, "setForbiddenHandler");
    renderAuthedApp();
    await openAccountMenu();
    expect(screen.getByText("Role: Senior analyst")).toBeVisible();

    // AuthedApp registers the denial handler on mount; the last non-null registration is the live one.
    const handlers = setForbidden.mock.calls.map(([handler]) => handler).filter((handler) => handler !== null);
    const onForbidden = handlers[handlers.length - 1];
    act(() => {
      onForbidden();
    });
    expect(await screen.findByText("Role: Analyst")).toBeVisible();
  });
});

describe("AuthedApp mid-session expiry", () => {
  // spec:web-ui/authenticated-entry-to-the-application/mid-session-expiry-returns-the-operator-to-login
  it("redirects to login when a background fetch returns 401 after a successful session probe", async () => {
    stubSessionThen401();
    renderAuthedApp();
    // The mount probe authenticates, the home view renders, its first /api/hosts fetch 401s, the
    // registered unauthorized handler flips auth -> anon, and AuthedApp navigates to /login.
    expect(await screen.findByText("LOGIN PAGE")).toBeInTheDocument();
  });
});
