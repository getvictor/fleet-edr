import { describe, it, expect, vi, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
function stubSessionThen401(permissions: string[] = []): ReturnType<typeof vi.fn> {
  const mock = vi.fn((input: unknown): Promise<FakeResponse> => {
    const url = String(input);
    if (url.includes("/api/session")) return Promise.resolve(makeResponse({ ...authedSession, permissions }, 200));
    return Promise.resolve(makeResponse(null, 401));
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

function renderAuthedApp(at = "/") {
  return render(
    <MemoryRouter initialEntries={[at]}>
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

// Each route is guarded by the action its own data needs. A rule's detail and its monitor records read surfaces the server gates
// on alert.read, and both carried no guard at all while the catalogue beside them carried a stricter one.
describe("route guards match the action the data needs", () => {
  // spec:web-ui/navigation-and-action-affordances-are-capability-gated/a-rule-s-detail-and-its-monitor-records-follow-the-catalogue
  it.each([
    { name: "a rule's detail", at: "/rules/suspicious_exec" },
    { name: "its monitor records", at: "/rules/suspicious_exec/monitor-records" },
  ])("presents $name to an operator holding alert.read", async ({ at }) => {
    stubAuthedSession([PermissionAction.AlertRead]);
    renderAuthedApp(at);
    // Rendered, not refused. The page's own empty state is beside the point; what is asserted is that the guard let it through.
    await waitFor(() => {
      expect(screen.queryByText(/don't have access/i)).not.toBeInTheDocument();
    });
  });

  // Coverage keeps its own path rather than moving under the catalogue. A fixed /rules/coverage would rank above /rules/{id} in
  // the router whatever the declaration order, so a rule with that identifier would be unreachable; this pins that it is not.
  // spec:web-ui/coverage-is-read-beside-the-rules-it-is-computed-from/a-rule-identifier-is-not-shadowed-by-the-coverage-surface
  it("opens a rule whose identifier is the word coverage, rather than the coverage surface", async () => {
    stubAuthedSession([PermissionAction.AlertRead]);
    // A real rule carrying that identifier, so the assertion is that ITS detail rendered. Asserting only the absence of the
    // coverage view passed on the unknown-rule fallback too, which the stub's empty list produces for any id: the test would
    // have held just as well if the route had resolved to nothing at all.
    vi.spyOn(api, "fetchRuleDocs").mockResolvedValue([
      { id: "coverage", techniques: [], doc: { title: "Coverage", summary: "", description: "", severity: "high", event_types: ["exec"] } },
    ]);
    renderAuthedApp("/rules/coverage");

    expect(await screen.findByRole("heading", { name: "Coverage" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Export JSON" })).toBeNull();
  });

  // The landing used to resolve to Coverage because Coverage was the one ungated entry, which guaranteed a ROUTE rather than a
  // page the operator could read: the surface then answered with its own 403 (issue #1144).
  // spec:web-ui/navigation-and-action-affordances-are-capability-gated/coverage-is-gated-rather-than-relied-on-as-a-landing
  it("tells an operator holding nothing that they lack access, rather than failing a read", async () => {
    stubAuthedSession([]);
    renderAuthedApp();
    expect(await screen.findByText(/don't have access/i)).toBeVisible();
    expect(screen.queryByText(/API error: 403/)).toBeNull();
  });
});

describe("AuthedApp mid-session expiry", () => {
  // spec:web-ui/authenticated-entry-to-the-application/mid-session-expiry-returns-the-operator-to-login
  it("redirects to login when a background fetch returns 401 after a successful session probe", async () => {
    // The session holds alert.read so the landing resolves to a surface that actually reads something. With no actions at all the
    // landing now renders the no-access state, which issues no request, so there would be no background 401 to expire on: that is
    // the point of gating every entry, and it would leave this test passing for the wrong reason.
    stubSessionThen401([PermissionAction.AlertRead]);
    renderAuthedApp();
    // The mount probe authenticates, the home view renders, its first background fetch 401s, the
    // registered unauthorized handler flips auth -> anon, and AuthedApp navigates to /login.
    expect(await screen.findByText("LOGIN PAGE")).toBeInTheDocument();
  });
});
