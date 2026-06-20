# Tasks

## Server

- [x] `server/config/config.go`: remove the 17 struct fields, parses, defaults, and the `composeDSN` path; export the default constants `cmd/main` now wires (`DefaultProcessInterval`, `DefaultProcessBatch`, `DefaultRetentionInterval`, `DefaultStaleProcessTTL`, `DefaultStaleProcessInterval`, `DefaultHostTokenLifetime`, `DefaultOIDCStateCookieTTL`, `DefaultOIDCScopes()`).
- [x] `server/cmd/fleet-edr-server/main.go` + `server/cmd/fleet-edr-ingest/main.go`: pass the default constants at the bootstrap call sites; keep all `Deps` parameters.
- [x] `server/httpserver/tls.go`: drop `TLSOptions.AllowTLS12` and make TLS 1.3 the unconditional floor.
- [x] `server/config/config_test.go`: drop the cases for removed knobs (MySQL compose, process interval/batch, OIDC scopes/cookie, audit knobs).

## Agent

- [x] `agent/config/config.go`: remove the 5 struct fields, parses, and defaults; export `DefaultBatchSize`, `DefaultUploadInterval`, `DefaultPruneAge`, `DefaultNetworkCoalesceWindow`, `DefaultQueueMaxBytes`.
- [x] `agent/cmd/fleet-edr-agent/main.go` + `agent/cmd/fleet-edr-agent-headless/main.go`: pass the default constants; keep `uploader.Config` / `headless.Options` / `queue.Options` / `coalesce.New` parameters.
- [x] `agent/config/config_test.go`: drop the cases for removed knobs.

## Docs + deploy

- [x] Scrub removed vars from `docs/install-server.md`, `docs/operations.md`, `docs/okta-setup.md`, `docs/breakglass.md`, `docs/threat-model.md`, `docs/quickstart-vm.md`, `Taskfile.yml`, `scripts/test-e2e-coverage.sh`, `packaging/nginx/multi-replica.conf`.

## Verification

- [x] `go build ./...`, `go vet`, server + agent config unit tests, agent consumer tests, httpserver test.
- [ ] Dev-server boot QA + macOS VM agent enroll/upload QA with the trimmed surface.
- [x] File the follow-up issue to move the detection allowlists to a DB/policy-backed config layer (getvictor/fleet-edr#459).
