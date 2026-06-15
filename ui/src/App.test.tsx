import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { AuthedApp } from "./App";
import { setUnauthorizedHandler, setForbiddenHandler } from "./api";

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
