import { useCallback, useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate } from "react-router-dom";
import { HostList } from "./components/HostList";
import { ProcessTreeView } from "./components/ProcessTree";
import { AlertList } from "./components/AlertList";
import { AttackCoverage } from "./components/AttackCoverage";
import { ApplicationControlRoutes } from "./components/ApplicationControl/ApplicationControlRoutes";
import { RuleDetail } from "./components/RuleDetail";
import { Login } from "./components/Login";
import { BreakGlassSetup } from "./components/BreakGlassSetup";
import { BreakGlassLogin } from "./components/BreakGlassLogin";
import { TopNav } from "./components/ui/TopNav";
import { currentSession, logout, Unauthorized401Error, SessionInfo, setForbiddenHandler } from "./api";
import { PermissionsProvider, RequirePermission } from "./permissions";
import { PermissionAction } from "./permissions-core";
import { createDedupedRunner } from "./dedupe";

type AuthState =
  | { status: "loading" }
  | { status: "anon" }
  // permissions is the operator's effective action set from the session probe, or
  // undefined when the server didn't return one (older server). Threaded into the
  // PermissionsProvider so the capability seam can gate nav + affordances.
  | { status: "authed"; user: SessionInfo["user"]; authMethod: string; permissions: string[] | undefined };

// Routes are top-level. /ui/login (and the break-glass pages) are
// public; /ui/* otherwise probes /api/session and gates
// rendering on a live session. The auth-state switch lives inside
// the router so route changes can drive re-checks (e.g. after a
// successful break-glass login the operator lands on /ui/ and the
// session probe runs there).
export function App() {
  return (
    <BrowserRouter basename="/ui">
      <Routes>
        {/* Public pre-auth pages */}
        <Route path="/login" element={<Login />} />
        <Route path="/admin/break-glass" element={<BreakGlassLogin />} />
        <Route path="/admin/break-glass/setup" element={<BreakGlassSetup />} />
        {/* Authed app */}
        <Route path="/*" element={<AuthedApp />} />
      </Routes>
    </BrowserRouter>
  );
}

// AuthedApp is everything behind the /api/session gate. On mount it
// probes the session; on 401 it redirects to /ui/login carrying the
// attempted path as ?next= so a successful sign-in returns the
// operator to where they were heading.
function AuthedApp() {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const info = await currentSession();
        if (controller.signal.aborted) return;
        setAuth({
          status: "authed",
          user: info.user,
          authMethod: info.auth_method ?? "local_password",
          permissions: info.permissions,
        });
      } catch (err) {
        if (controller.signal.aborted) return;
        if (!(err instanceof Unauthorized401Error)) {
          // Network / 5xx — same outcome as 401: send to login. The
          // server is the source of truth; rendering with stale
          // state is worse than showing the sign-in page.
          // eslint-disable-next-line no-console
          console.warn("session probe failed", err);
        }
        setAuth({ status: "anon" });
      }
    })();
    return () => { controller.abort(); };
    // One-shot probe on mount. Background 401s from individual
    // /api/* fetches already throw Unauthorized401Error and call
    // sites surface that to flip auth -> 'anon'; re-running on every
    // route change cost an extra /api/session round-trip per
    // navigation and made the app flicker back to 'loading'
    // mid-route.
  }, []);

  useEffect(() => {
    // When the server returns a genuine 403 for an action the UI believed was
    // permitted (e.g. the operator's role was changed after the session probe),
    // refresh the permission set so the now-stale affordance is hidden on the next
    // render. createDedupedRunner collapses a burst of simultaneous denials into a
    // single /api/session refetch rather than a request storm (the throttle the
    // capability-gating spec requires). A failed/again-denied refetch is a no-op for
    // auth state: the per-fetch 401 path handles session loss; a repeat 403 just
    // means still-denied.
    const refresh = createDedupedRunner(async () => {
      const info = await currentSession();
      setAuth((prev) => (prev.status === "authed" ? { ...prev, permissions: info.permissions } : prev));
    });
    setForbiddenHandler(refresh);
    return () => { setForbiddenHandler(null); };
  }, []);

  const handleLogout = useCallback(async () => {
    await logout().catch(() => { /* best-effort: clear locally regardless */ });
    setAuth({ status: "anon" });
    await navigate("/login", { replace: true });
  }, [navigate]);

  if (auth.status === "loading") {
    return <div className="app-loading" />;
  }

  if (auth.status === "anon") {
    // Pass the current path as ?next= so the IdP returns the
    // operator to the page they tried to reach. Strip /ui/ from
    // basename-relative paths since react-router gives us the
    // path AFTER the basename.
    const next = location.pathname === "/" ? undefined : `/ui${location.pathname}${location.search}`;
    const search = next ? `?next=${encodeURIComponent(next)}` : "";
    return <Navigate to={`/login${search}`} replace />;
  }

  return (
    <PermissionsProvider permissions={auth.permissions}>
      <TopNav
        user={auth.user}
        authMethod={auth.authMethod}
        onLogout={() => { handleLogout().catch(() => undefined); }}
      />
      <main className="app-page">
        <Routes>
          <Route path="/" element={<HostList />} />
          <Route path="/alerts" element={<AlertList />} />
          <Route
            path="/app-control/*"
            element={(
              <RequirePermission action={PermissionAction.AppControlRead} surface="Application control">
                <ApplicationControlRoutes />
              </RequirePermission>
            )}
          />
          <Route path="/coverage" element={<AttackCoverage />} />
          <Route path="/rules/:ruleId" element={<RuleDetail />} />
          <Route path="/hosts/:hostId" element={<ProcessTreeView />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </PermissionsProvider>
  );
}
