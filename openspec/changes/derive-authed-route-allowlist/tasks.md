## 1. Recording primitive

- [x] 1.1 Add `httpserver.Router` (Handle + HandleFunc; satisfied by `*http.ServeMux`)
- [x] 1.2 Add `httpserver.RecordingRouter` (forwards to an inner Router, records patterns in order, `Patterns()` returns a copy)
- [x] 1.3 Unit-test RecordingRouter (records + forwards; Patterns is a copy; `*http.ServeMux` satisfies Router)

## 2. Thread the interface through registration

- [x] 2.1 Change the five contexts' `RegisterAuthedRoutes` to accept `httpserver.Router`
- [x] 2.2 Change the operator handlers' `RegisterRoutes` (response, endpoint, rules, appcontrol, detection) that the bootstraps delegate to
- [x] 2.3 Bodies unchanged (HandleFunc only); add the httpserver import where missing; drop a now-unused net/http import

## 3. Derive the allowlist

- [x] 3.1 Extract `mountAuthed(outer, protect, register)`: register via a RecordingRouter, wrap the API mux, mount exactly the recorded patterns
- [x] 3.2 `registerSessionRoutes` calls `mountAuthed`; delete the hand-maintained allowlist slice
- [x] 3.3 `buildMux`-level test: a registered authed route is reachable as the session auth failure (JSON), not the SPA catch-all

## 4. Docs + traceability + gates

- [x] 4.1 spectrace marker tying the test to the `server-rest-api` scenario
- [x] 4.2 `openspec validate derive-authed-route-allowlist --strict`; `go run ./tools/spectrace check --strict`
- [x] 4.3 `go build ./...`, `go test` (httpserver + cmd + all five contexts), `task lint:go`, `task lint:dashes`
