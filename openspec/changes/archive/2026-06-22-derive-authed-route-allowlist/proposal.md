## Why

`buildMux` mounts the session-protected API onto the outer router through a hand-maintained allowlist (a `for _, p := range []string{...}` slice in `server/cmd/fleet-edr-server/main.go`). Each bounded context registers its authed routes on the API mux via `RegisterAuthedRoutes`, but a route only actually serves traffic if its exact pattern is *also* in that slice. The two silently drift: a route registered but missing from the slice falls through to the `/` single-page-app catch-all and returns the SPA HTML (302 / index.html), which the UI's `fetch` then parses as JSON and surfaces as `Unexpected token '<'`.

This has bitten twice (#158 app-control list endpoint, #375 SSO settings), each time caught only by live dev-server QA because the unit/integration tests mount `RegisterAuthedRoutes` on a bare mux and bypass the composed allowlist entirely. Issue #463 asks for a durable guard so it cannot recur a third time.

## What Changes

- Add a `httpserver.Router` interface (`Handle` + `HandleFunc`, satisfied by `*http.ServeMux`) and a `httpserver.RecordingRouter` that forwards registrations to an inner router while recording the registered patterns.
- Change every authed route-registration method to accept `httpserver.Router` instead of `*http.ServeMux` (the 5 contexts' `RegisterAuthedRoutes` and the operator handlers' `RegisterRoutes` they delegate to). `*http.ServeMux` satisfies the interface, so every call site compiles unchanged and the method bodies are untouched.
- Derive the session-protected allowlist in `buildMux`: register every context's authed routes through one `RecordingRouter`, then mount exactly the recorded patterns on the session-protected boundary. Delete the hand-maintained slice. A registered authed route is now mounted automatically, so the drift is structurally impossible rather than guarded after the fact.
- Add a `buildMux`-level test that a route registered through the authed-route registration path is reachable through the composed router as the session auth failure (JSON), not the SPA HTML catch-all.

Out of scope: the agent-token allowlist in `registerHostRoutes` follows the same hand-maintained pattern but is smaller, stable, and not the reported bug (an agent does not parse the SPA shell as JSON); the same `RecordingRouter` primitive could derive it in a follow-up.

## Capabilities

### Modified Capabilities

- `server-rest-api`: the session-protected route surface is derived from what the contexts register, so every registered authed route is reachable through the composed router with its session-authentication boundary applied and never falls through to the SPA catch-all.

## Impact

- Code: `server/httpserver` (new `Router` + `RecordingRouter`), the route-registration signatures across all five bounded contexts (`*http.ServeMux` to `httpserver.Router`, bodies unchanged), and `server/cmd/fleet-edr-server/main.go` (`registerSessionRoutes` derives the allowlist via `mountAuthed`; the hand-maintained slice is removed).
- Behavior: no observable change to any existing route; the same routes serve the same responses. The only difference is that a future authed route can no longer be registered without being allowlisted.
- Rollback is a code revert. No data, schema, wire-format, or agent-protocol change.
