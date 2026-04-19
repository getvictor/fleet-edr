import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { HostList } from "./components/HostList";
import { ProcessTreeView } from "./components/ProcessTree";
import { AlertList } from "./components/AlertList";
import { Login } from "./components/Login";
import { TopNav } from "./components/ui/TopNav";
import { currentSession, logout, Unauthorized401Error, SessionInfo } from "./api";

type AuthState =
  | { status: "loading" }
  | { status: "anon" }
  | { status: "authed"; user: SessionInfo["user"] };

// Phase 3: the UI probes GET /api/v1/session on mount. On 200 we render the app; on
// 401 we render the Login component. The old sessionStorage "edr_api_key" probe is
// gone — the cookie is HttpOnly so JS can't see it directly, and the server is the
// source of truth for "am I logged in?".
export function App() {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    // `void` marks the floating promise as intentional for
    // @typescript-eslint/no-floating-promises. We don't need to await it — React's
    // useEffect already handles async component lifecycle via the cleanup closure.
    void (async () => {
      try {
        const info = await currentSession();
        if (!controller.signal.aborted) setAuth({ status: "authed", user: info.user });
      } catch (err) {
        if (controller.signal.aborted) return;
        if (err instanceof Unauthorized401Error) {
          setAuth({ status: "anon" });
        } else {
          // Unknown error (network, 5xx) — fall back to the login page rather than
          // render with no data. The user can retry after fixing the network.
          setAuth({ status: "anon" });
        }
      }
    })();
    return () => { controller.abort(); };
  }, []);

  async function handleLogout() {
    await logout().catch(() => { /* Logout failures are best-effort; we still clear locally. */ });
    setAuth({ status: "anon" });
  }

  if (auth.status === "loading") {
    // Tiny blank state — the session probe is ~100ms; rendering a spinner here caused
    // more layout flash than the blank did in informal testing.
    return <div className="app-loading" />;
  }

  if (auth.status === "anon") {
    return (
      <Login
        onLogin={() => {
          // The login() call in the Login component already set the CSRF token; we
          // just need to re-read the session to populate the user info for TopNav.
          void (async () => {
            try {
              const info = await currentSession();
              setAuth({ status: "authed", user: info.user });
            } catch { /* shouldn't happen immediately after a successful login */ }
          })();
        }}
      />
    );
  }

  return (
    <BrowserRouter basename="/ui">
      <TopNav user={auth.user} onLogout={() => { void handleLogout(); }} />
      <main className="app-page">
        <Routes>
          <Route path="/" element={<HostList />} />
          <Route path="/alerts" element={<AlertList />} />
          <Route path="/hosts/:hostId" element={<ProcessTreeView />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </BrowserRouter>
  );
}
