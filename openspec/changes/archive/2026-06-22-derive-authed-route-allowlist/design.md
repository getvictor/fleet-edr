# Design: derive the authed-route allowlist (#463)

## The constraint that shapes the fix

Go's `http.ServeMux` exposes no API to enumerate the patterns registered on it (the pattern map is unexported, and Go 1.22's method+path routing did not add introspection). So neither "derive the allowlist" nor "test that every registered route is reachable" can inspect the API mux after the fact. Both have to capture patterns *at registration time*. The only way to capture them is to have `RegisterAuthedRoutes` register onto something we control instead of a concrete `*http.ServeMux`.

## Decision: a Router interface + a recording wrapper, then derive

- `httpserver.Router` is the minimal subset the registration bodies use: `Handle` + `HandleFunc`. `*http.ServeMux` already satisfies it, so changing the parameter type from `*http.ServeMux` to `httpserver.Router` leaves every call site compiling and every method body unchanged. The change is wide (every authed registration method, and the operator-handler `RegisterRoutes` the context bootstraps delegate to) but shallow and mechanical.
- `httpserver.RecordingRouter` wraps a `Router`, forwards every `Handle`/`HandleFunc` to it, and records the pattern. `buildMux` registers all contexts through one `RecordingRouter` over the API mux, then mounts exactly `Patterns()` on the session-protected boundary.

Because the mounted set *is* the registered set, a route can no longer be registered-but-not-mounted. The bug class is eliminated, not merely guarded, which is why this is preferred over a test that only asserts the hand-maintained list stays in sync.

## Alternatives considered

- **A test that re-lists the routes.** Moves the drift into the test (the test's route list can fall out of sync just like the slice did). Rejected: it does not make drift impossible.
- **A data-driven route table per context** (`var routes = []Route{...}` consumed by both registration and an exporter). More invasive than the interface seam (rewrites how every handler registers) for no extra safety over recording.
- **Reflecting/AST-parsing the source for patterns.** Fragile and indirect. Rejected.

## Testability

`registerSessionRoutes` takes concrete context types, which are expensive to construct in a unit test (DB, signing keys, OPA engine). The derive-and-mount core is therefore extracted into `mountAuthed(outer, protect, register)`, which `registerSessionRoutes` calls with the real dependencies and the test calls with a stub `protect` (returns 401 JSON) and a `register` that registers a probe route. The test asserts the probe route is reachable as the auth failure (JSON), not the SPA HTML catch-all, and that a never-registered route still falls through to the SPA. That exercises the real composition path, not a re-implementation.

## Out of scope

The agent-token allowlist in `registerHostRoutes` is the same hand-maintained shape but smaller, stable, and not the reported bug (an agent does not parse the SPA shell). The same `RecordingRouter` primitive can derive it later.
