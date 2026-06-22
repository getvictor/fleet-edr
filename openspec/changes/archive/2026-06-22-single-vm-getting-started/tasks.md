# Single-VM getting-started with an operator-controlled edge: tasks

## 1. Quickstart stack

- [x] `docker-compose.quickstart.yml`: MySQL + server + Caddy. Server in proxy-terminated TLS mode (`EDR_TLS_TERMINATED_BY_PROXY=1`), plaintext on the private network, no host port published; only Caddy is internet-facing (80/443). Secrets via docker-secret files. Forwards `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_HEADERS` / `OTEL_RESOURCE_ATTRIBUTES` from `.env`.
- [x] `packaging/caddy/Caddyfile`: `{$EDR_DOMAIN} { reverse_proxy http://server:8088 }`. Auto-HTTPS via Let's Encrypt, plain proxy, no managed ruleset.
- [x] `bootstrap.sh`: one command (`EDR_DOMAIN=... EDR_VERSION=... ./bootstrap.sh`). Idempotent secret generation (never rotates the enroll secret out from under enrolled agents), writes `.env`, brings the stack up, prints the enroll secret + break-glass grep.
- [x] `bootstrap.sh`: write the secret files `0644`, not `0600`. Compose bind-mounts a file secret with the host file's owner and mode (uid/gid/mode long-syntax options are Swarm only), and the server image runs as nonroot, so a `0600` file owned by the host user is unreadable inside the container and the server crash-loops on "permission denied". Caught by the end-to-end VM run. Same fix applied to `docker-compose.prod.README.md`.

## 2. Docs

- [x] `docs/quickstart-vm.md`: prereqs, six steps, operations (upgrade, backups, enroll-secret rotation, OIDC later), a "Send telemetry to a collector" OTel section, and a "Why no WAF here" section.
- [x] `docs/deploy-render.md`: `[!WARNING]` block at the top (edge WAF blocks agent telemetry, cannot self-disable, two workarounds, pointer to the quickstart as the recommended path).
- [x] `README.md` + `docs/README.md`: promote the single-VM quickstart to the recommended getting-started path; demote Render to a caveated alternative.

## 3. Packaging fix

- [x] `docker-compose.prod.yml`: add `EDR_SECRET_KEY_FILE: /run/secrets/secret_key` + the `secret_key` docker-secret. The server requires the deployment root secret unconditionally (`server/config/config.go` `loadSecretKey`); the prod stack omitted it and would fail to boot.
- [x] `docker-compose.prod.README.md`: generate `secrets/secret_key` (`openssl rand -hex 32`) in one-time setup; note it is effectively un-rotatable (rotating invalidates every enrolled host).

## 4. Spec

- [x] `server-event-ingestion` delta: ADDED requirement "Ingest acceptance is content-neutral" with the attack-signature-accepted and never-content-block scenarios.
- [x] `server-availability` delta: ADDED requirement "The default getting-started deployment controls its own edge" with the attack-signature-telemetry-reaches-the-server scenario.

## 5. Tests

- [x] `server/detection/internal/intake/handler_test.go`: `TestParseAndValidateIngestBody_ContentNeutral` pins that an attack-signature batch parses identically to a benign one and that the parser's status surface never includes `403`. Scenario markers on both subtests.
- [x] `server/detection/internal/tests/integration_test.go`: `TestIngest_AttackSignatureTelemetryReachesServer` POSTs an attack-signature batch through the real HTTP ingest path and asserts `200` + both events persisted. Scenario marker for the `server-availability` topology requirement.

## 6. Verification

- [x] `go test ./server/detection/internal/intake/` green.
- [x] `go test -tags=integration ./server/detection/internal/tests/ -run TestIngest_AttackSignatureTelemetryReachesServer` green (real MySQL).
- [x] `docker compose -f docker-compose.quickstart.yml config` renders with `EDR_DOMAIN`/`EDR_VERSION` set; `bash -n bootstrap.sh` clean.
- [ ] `openspec validate single-vm-getting-started --strict`; spectrace; dash + markdown-prose lints.
- [x] End-to-end on a throwaway Azure VM (`temp.fleetdm.site`): Caddy issued the Let's Encrypt cert (verified trusted), `/readyz` 200 over public HTTPS, a host enrolled, and an attack-signature batch (reverse shell + C2 URL + SQL-injection) uploaded through the edge returned `200 {"accepted":2}`. The same body without a token returned the app's `401` (`via: 1.1 Caddy`), never a content-inspecting `403`. Surfaced and fixed the `0600` secret-file permission bug above.
