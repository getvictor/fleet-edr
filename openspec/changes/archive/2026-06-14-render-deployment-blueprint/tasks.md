# Render deployment blueprint: tasks

## 1. Server config

- [x] `config.go`: add `TLSTerminatedByProxy`, parse `EDR_TLS_TERMINATED_BY_PROXY`; gate loadTLSConfig (skip cert requirement when set, reject flag + cert files together).
- [x] `config.go`: compose `EDR_DSN` from `EDR_MYSQL_*` parts when `EDR_DSN` is unset; explicit DSN wins.
- [x] `main.go` configureTLS: skip TLS wiring + warn in proxy mode (leaves `srv.TLSConfig` nil).
- [x] `serve.go` RunAndShutdown: serve plaintext HTTP when `srv.TLSConfig` is nil, else TLS.
- [x] Config tests: proxy-mode boot, proxy+cert mutual exclusion, DSN compose, explicit-DSN-wins, partial-parts error.

## 2. Blueprint + docs

- [x] `render.yaml`: web service + bundled MySQL pserv, proxy-TLS, DSN parts via `fromService`, `/readyz` health check.
- [ ] `docs/deploy-render.md`: deploy walkthrough + hand-off to fleet-deployment.md.
- [ ] `docs/README.md`: link the Render path from the getting-started shape.

## 3. Spec

- [x] `server-availability` spec: ADDED requirement "TLS may be terminated by a front proxy" with three scenarios; markers in config tests.

## 4. Verification

- [ ] `go test ./server/config/...` green; `go build ./server/...`.
- [ ] Local smoke: run the image with `EDR_TLS_TERMINATED_BY_PROXY=1` + a MySQL, `curl http://localhost:PORT/readyz` returns 200.
- [ ] `openspec validate render-deployment-blueprint`, spectrace, gofmt, golangci-lint, markdown + dash lints, render.yaml parses.
