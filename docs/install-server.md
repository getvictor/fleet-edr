# Install the Fleet EDR server

The reference deployment is Docker Compose: MySQL + the server image, with a TLS-terminating ingress in front. The stack is sized for a single customer with 10 to 500 endpoints. Pick a topology below, then follow the setup steps.

## Deployment topology

The server tier is stateless: it holds no in-process state that outlives a request, so any replica can serve any request and durable state lives in the shared MySQL (see [`adr/0010-stateless-server.md`](adr/0010-stateless-server.md)). That makes two topologies available.

### Multi-replica (high availability): reference

Two or more server replicas behind a load balancer, in front of one MySQL. This is the recommended topology: a replica can be drained and restarted (or rolled to a new version) without a maintenance window, because the load balancer routes around a draining replica and sessions are MySQL-backed, so there are no sticky sessions to strand. Use `packaging/docker-compose-multi-replica.yml` (two replicas + MySQL + an NGINX proxy); `packaging/haproxy/multi-replica.cfg` is a drop-in HAProxy alternative that adds active `/readyz` health checks. The setup steps below apply unchanged except that you also generate a shared `secret_key` secret (`openssl rand -hex 32 > secrets/secret_key`), which every replica must share so the derived keys match (a token hashed or a session minted on one validates on another).

Properties this topology relies on, each pinned by a test in the `server-availability` spec: the processor scales across replicas via `SKIP LOCKED`; sessions and CSRF tokens validate on any replica; the periodic maintenance tasks run on exactly one replica via MySQL advisory locking; and schema migrations are applied under an advisory lock so a rolling upgrade never runs two migration applies against one database at once.

The MySQL instance is the remaining single point of failure; bring your own replicated/managed MySQL for an HA datastore (out of scope here).

### Single-replica (small pilot)

One server replica + MySQL, from the root `docker-compose.prod.yml`. Simplest to operate and fine for a pilot, but a server restart or upgrade is a brief maintenance window rather than a hitless rollout. Move to the multi-replica topology when you need upgrades without downtime.

## Availability and SLA

The control-plane availability target for the multi-replica topology is **99.9%** (the management, query, ingest, and alerting plane: the UI, the API, and `/api/events` ingestion). The full architecture rationale is in [ADR-0011](adr/0011-ha-architecture.md).

How it reaches that: a replica can crash, drain, or roll to a new version without taking the control plane down, because MySQL-backed sessions let any replica serve any request and the load balancer pulls a draining replica from rotation. With the HAProxy config (or NGINX Plus) that pull is active, driven by `/readyz` polling, so a replica is removed before a request fails; the default open-source NGINX has only passive failover (it marks a replica down after failed forwards). A [rolling upgrade](operations.md#rolling-upgrade-multi-replica) is therefore not a maintenance window.

**Endpoint protection does not depend on control-plane availability:**

- **Enforcement continues during an outage.** Application-control block decisions are made in the macOS system extension from a cached policy snapshot, not by a server round-trip, so a server or network outage does not open a hole in enforcement.
- **No endpoint data is lost (up to the queue cap).** When the server is unreachable the agent buffers events in its local SQLite queue and uploads them when the server returns; `edr.agent.queue.dropped` increments only if the queue hits its cap. Detection and alerting run server-side, so alerts for events captured during an outage are generated when the backlog uploads (delayed, not lost).

Three caveats on the SLA:

1. **It is the control plane, not your infrastructure.** The 99.9% target is the EDR server tier. It is conditional on the load balancer and MySQL you operate being available; the EDR does not monitor or guarantee those.
2. **MySQL is a single point of failure in the reference stack.** v0.2.0 ships a single MySQL; the customer brings a replicated or managed MySQL for a fully HA datastore. A MySQL outage takes the control plane down regardless of how many server replicas are running (endpoint enforcement still continues, per above).
3. **Single region, single MySQL writer.** There is no multi-region or active-active deployment in v0.2.0; geo-distribution and read-routing are deferred to a later release.

## Prerequisites

- A Linux host with Docker Engine 24+ and Docker Compose v2 (`docker compose`, not `docker-compose`).
- 4 GB RAM, 2 CPU cores, 20 GB disk.
- A hostname + TLS certificate (see "TLS setup" below), or an intention to run without TLS for a lab.
- Inbound TCP to the server's ingress (default port 8088). Outbound to nothing except your OTel collector if you enable metrics.

## Setup

### 1. Choose a directory

Anywhere; the examples assume `/srv/fleet-edr/`.

```sh
sudo mkdir -p /srv/fleet-edr
sudo chown "$USER" /srv/fleet-edr
cd /srv/fleet-edr
```

### 2. Get the compose file

```sh
curl -fsSL -o docker-compose.prod.yml \
    https://raw.githubusercontent.com/getvictor/fleet-edr/main/docker-compose.prod.yml
```

**For the multi-replica HA topology**, use the packaging stack instead of the single-replica file above. It references sibling config files (the NGINX or HAProxy proxy config), so fetch the whole `packaging/` directory rather than a single file:

```sh
git clone --depth 1 https://github.com/getvictor/fleet-edr.git
cd fleet-edr/packaging   # docker-compose-multi-replica.yml + nginx/ + haproxy/ live here
```

The remaining steps are identical; create `secrets/` and `tls/` inside `packaging/`.

### 3. Create secret files

Three secret files live under `./secrets/` with mode 0600. Docker Compose bind-mounts them into the server + mysql containers as `/run/secrets/<name>`. None of the values land in any env block or `docker inspect` output.

```sh
mkdir -p secrets
MYSQL_PASS=$(openssl rand -hex 24)
printf '%s' "$MYSQL_PASS" > secrets/mysql_root
printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$MYSQL_PASS" > secrets/edr_dsn
ENROLL_SECRET=$(openssl rand -hex 32)
printf '%s' "$ENROLL_SECRET" > secrets/enroll_secret
chmod 0600 secrets/*
```

**For the multi-replica HA topology**, also generate the shared root secret. Every replica mounts the same key so the derived host-token pepper and cookie signing key match across replicas (a token hashed or a session minted on one validates on another):

```sh
openssl rand -hex 32 > secrets/secret_key
chmod 0600 secrets/secret_key
```

The `edr_dsn` file contains the same MySQL password embedded into a Go DSN. The server reads it via the `EDR_DSN_FILE` pattern (see `server/config/file_env.go`) so the password never appears in a compose env block.

Keep `MYSQL_PASS` and `ENROLL_SECRET` somewhere safe. You'll paste `ENROLL_SECRET` into your MDM install-script config when you deploy agents.

### 4. TLS setup

Two options.

**Option A: let the server terminate TLS.** Drop `fullchain.pem` + `privkey.pem` into `./tls/` (certbot output works directly). The compose bind-mounts `./tls` read-only into the server container.

```sh
mkdir -p tls
cp /etc/letsencrypt/live/edr.example.com/fullchain.pem tls/
cp /etc/letsencrypt/live/edr.example.com/privkey.pem tls/
chmod 0644 tls/fullchain.pem
chmod 0600 tls/privkey.pem
```

In your `.env` (next step), set:

```text
EDR_TLS_CERT_FILE=/tls/fullchain.pem
EDR_TLS_KEY_FILE=/tls/privkey.pem
```

**Option B: terminate TLS upstream (nginx, Caddy, an ALB, Cloudflare Tunnel).** The proxy is the external HTTPS endpoint. By default the proxy-to-EDR hop also runs over TLS (issue #140 makes the server terminate TLS itself): issue the proxy-to-backend cert from your internal CA or reuse the public cert, mount it under `./tls/`, and the env-var shape is identical to Option A. If your platform cannot present a backend certificate (most PaaS edges, including Render, proxy plaintext to the service), set `EDR_TLS_TERMINATED_BY_PROXY=1` instead and omit the cert files: the server then listens plaintext HTTP on the assumption that the proxy terminates TLS in front of it. The flag and cert files are mutually exclusive. For the Render one-click path see [deploy-render.md](deploy-render.md).

### 5. Pin a version in .env

```sh
cat > .env <<'EOF'
EDR_VERSION=v0.2.0
OTEL_EXPORTER_OTLP_ENDPOINT=
EOF
```

Use the exact tag from the [Releases page](https://github.com/getvictor/fleet-edr/releases). `latest` is fine for a lab but unsafe for a pilot because the digest drifts silently on each release.

### 6. Boot the stack

```sh
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

MySQL starts first (healthcheck gates the server), then the server image pulls from ghcr.io and comes up.

## Verify

### Readiness probe

TLS-terminated deployment:

```sh
curl -s https://edr.example.com/readyz | jq .
```

If you're running with a self-signed cert (lab / air-gapped pilot), either add the CA to the local trust store, pass `--cacert /path/to/ca.pem`, or temporarily use `-k` for this probe. Don't paper over a trust failure with `-k` in an automation script.

Local dev deployment (`task dev:server`, issue #140: TLS by default with the self-signed cert from `task dev:certs`):

```sh
curl -sk https://localhost:8088/readyz | jq .
```

`-k` is acceptable here because the cert is a known self-signed dev cert. Install mkcert for warning-free dev (`brew install mkcert nss && mkcert -install`) and it validates without the flag.

Expect:

```json
{
  "status": "ok",
  "version": "v0.2.0",
  "uptime_seconds": 12,
  "checks": {
    "db": { "status": "ok", "latency_ms": 2 }
  }
}
```

If `db.status` is `error` / `unavailable`, MySQL isn't reachable. Check `docker compose logs mysql`.

### Redeem the break-glass admin account

The server seeds a single break-glass admin row on first boot with a NULL password. cmd/main prints a one-shot redemption URL to stderr; the operator opens that URL in a browser to set a password and register a WebAuthn credential (atomic redemption). The URL prints on every boot until the credential is stored; once it is, the banner is silent.

```sh
docker compose -f docker-compose.prod.yml --env-file .env logs server \
    | grep -B 1 -A 4 BREAK-GLASS
```

Expected output:

```text
================================================================
BREAK-GLASS ADMIN SETUP (one-shot redemption URL - open in a browser)
  Email: admin@fleet-edr.local
  URL:   https://edr.example.com/admin/break-glass/setup?token=<random>
  TTL:   1h0m0s
================================================================
```

Open the URL within the TTL (default 1h, tunable via `EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL`). The form takes a password (≥ 12 runes) and prompts the authenticator to register a WebAuthn credential; the three writes (token consume + password set + credential persist) commit in a single transaction so a partial failure leaves the token reusable. If the redemption window lapses, restart the server: a fresh token + URL print on every boot until the credential lands.

### Log into the UI

Production deployments authenticate via OIDC: open `https://edr.example.com/ui/` and follow "Continue with single sign-on" into your IdP. The break-glass account at `/admin/break-glass` exists for IdP-down recovery only.

Local dev (`task dev:server`, `https://localhost:8088/ui/` - accept the self-signed cert once if mkcert isn't installed) typically uses the seeded break-glass account because no production IdP is configured. The hosts page is empty until the first agent enrolls.

## Configuration reference

Non-exhaustive; see `server/config/config.go` for every knob. Anything unset uses the documented default.

| Env var | Required | Default | Purpose |
| --- | --- | --- | --- |
| `EDR_DSN` / `EDR_DSN_FILE` | yes | none | MySQL DSN, `user:pass@tcp(host:port)/db?parseTime=true` |
| `EDR_ENROLL_SECRET` / `EDR_ENROLL_SECRET_FILE` | yes | none | Shared secret agents present at enrollment |
| `EDR_LISTEN_ADDR` | no | `:8088` | TCP address the HTTPS server binds |
| `EDR_TLS_CERT_FILE` | **yes** | none | PEM cert. Required unless `EDR_TLS_TERMINATED_BY_PROXY=1`; the server has no _unguarded_ plaintext-HTTP mode (issue #140) |
| `EDR_TLS_KEY_FILE` | **yes** | none | PEM key (pair with cert) |
| `EDR_TLS_ALLOW_TLS12` | no | 0 | Allow TLS 1.2 (default is 1.3-only) |
| `EDR_SHUTDOWN_DRAIN` | no | 30s | On SIGTERM the server reports `/readyz` 503 and keeps serving for this long before closing the listener, so a load balancer drains the replica from rotation first. 0 disables the wait (immediate shutdown) |
| `EDR_ENROLL_RATE_PER_MIN` | no | 30 | Per-IP enroll rate limit |
| `EDR_RETENTION_DAYS` | no | 30 | Event TTL, 0 disables retention |
| `EDR_RETENTION_INTERVAL` | no | 1h | How often the retention job runs |
| `EDR_LAUNCHAGENT_ALLOWLIST` | no | none | Comma-separated absolute paths the `persistence_launchagent` rule treats as benign |
| `EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST` | no | none | Comma-separated code-signing team IDs the `privilege_launchd_plist_write` rule treats as benign |
| `EDR_SUDOERS_WRITER_ALLOWLIST` | no | none | Comma-separated writer-process absolute paths the `sudoers_tamper` rule treats as benign; alerts may surface either `/etc/sudoers...` or `/private/etc/sudoers...` because `/etc` is a symlink and ES reports the path as opened |
| `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` | no | none | Comma-separated non-shell parent absolute paths the `suspicious_exec` rule treats as benign roots for BOTH trigger shapes: the `parent → shell → /tmp/binary` chain AND the `parent → shell` followed by an outbound network connection. Recommended on fleets with interactive admin SSH: `/usr/libexec/sshd-session,/Applications/Terminal.app/Contents/MacOS/Terminal,/Applications/iTerm.app/Contents/MacOS/iTerm2`. Leave empty on servers where interactive SSH is unusual |
| `EDR_DISABLED_RULES` | no | none | Comma-separated rule IDs to drop from the detection registry at boot. A disabled rule is gone from the engine's active set AND from `GET /api/rules`, so it never evaluates against any batch and never produces alerts until it is re-enabled (requires a server restart). Unknown IDs WARN at boot but don't fail it, so a stale config doesn't take a deployment down. Use the rule IDs printed by `GET /api/rules` (e.g. `suspicious_exec,osascript_network_exec`) |
| `EDR_LOG_LEVEL` | no | info | `debug` / `info` / `warn` / `error` |
| `EDR_LOG_FORMAT` | no | json | `json` or `text` |
| `EDR_SECRET_KEY` / `EDR_SECRET_KEY_FILE` | yes | none | Deployment root secret (≥ 32 bytes). Every long-lived server-side key derives from it via HKDF: the host-token HMAC pepper and the cookie signing key (OIDC state cookie + WebAuthn registration session). Required on every boot. Rotating it invalidates every host token (fleet-wide re-enroll) plus every session and in-flight ceremony; see [operations.md](operations.md#edr-root-secret) |
| `EDR_BREAKGLASS_RP_ID` | yes in prod | none | WebAuthn relying-party identifier (registrable host, no scheme, no port). Changing post-deploy invalidates every registered credential. See [breakglass.md](breakglass.md#configuration) |
| `EDR_BREAKGLASS_RP_ORIGINS` | yes in prod | none | Comma-separated absolute URLs accepted as the WebAuthn origin (e.g. `https://edr.example.com`). See [breakglass.md](breakglass.md#configuration) |
| `EDR_BREAKGLASS_RP_DISPLAY_NAME` | no | `EDR Break-glass` | Operator-visible name shown during authenticator enrollment |
| `EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL` | no | 1h | Go duration. Lifetime of the first-boot redemption URL |
| `EDR_BREAKGLASS_IP_ALLOWLIST` | no | none | Comma-separated CIDR list gating `/admin/break-glass*`. Off-list callers get a 404 |
| `EDR_SESSION_IDLE_TIMEOUT` | no | 8h | Inactivity cap for OIDC-minted sessions. Sliding window on last_seen_at |
| `EDR_SESSION_ABSOLUTE_TIMEOUT` | no | 24h | Hard age cap for OIDC-minted sessions (forces periodic re-auth) |
| `EDR_REAUTH_WINDOW` | no | 30m | Freshness window for destructive actions (host.isolate, host.kill_process, host.run_script, critical alert resolve) |
| `EDR_BREAKGLASS_SESSION_IDLE_TIMEOUT` | no | 15m | Strict idle cap for recovery sessions |
| `EDR_BREAKGLASS_SESSION_ABSOLUTE_TIMEOUT` | no | 1h | Absolute cap for recovery sessions |
| `EDR_AUTH_ALLOW_NO_OIDC` | no | 0 | Dev-only opt-in to boot in break-glass-only mode. Production refuses to start without OIDC unless this is `1`. See [okta-setup.md](okta-setup.md) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | none | `host:port` of an OTLP/gRPC collector; unset disables metrics export |

Every string knob accepts a `_FILE` variant (`EDR_ENROLL_SECRET_FILE`, `EDR_DSN_FILE`, etc.) that points at a file whose trimmed contents become the value. That's how the compose stack delivers secrets.

## OTel metrics and logs

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to your collector (SigNoz, Tempo, Datadog OTel, etc.). The server exports:

- **Traces** for every HTTP request + DB query.
- **Logs** via `otelslog` with `service.name=fleet-edr-server`.
- **Metrics**. Counters appear in the backend only after their first non-zero sample, so a fresh deploy won't show, for example, the retention or alert series until those events first occur.

  - `edr.events.ingested` (counter, by `host_id`): events accepted by `POST /api/events`.
  - `edr.alerts.created` (counter, by `rule_id` + `severity`): alerts raised by detection.
  - `edr.enrolled.hosts` (gauge): current non-revoked enrollments.
  - `edr.offline.hosts` (gauge): hosts unseen longer than the offline threshold (5 min).
  - `edr.retention.rows_deleted` (counter): event rows pruned per retention run.
  - `edr.retention.processes.rows_deleted` (counter): process-graph rows pruned per retention run.
  - `edr.processes.ttl_reconciled` (counter): processes whose exit was synthesized by the freshness-TTL reconciler (missed-exit fallback).
  - `edr.agent.queue.dropped` (counter): agent-side queue drops reported back.
  - `edr.audit.write_failures` (counter): audit-row INSERT failures; any non-zero value means the append-only audit contract is broken, so alert on it.
  - `http.server.request.duration` (histogram, by route + method + status): request volume and latency.
  - `db.sql.latency` (histogram) and `db.sql.connection.*` (connection-pool stats): DB call latency and pool health, from the otelsql driver instrumentation.

  See [operations.md](operations.md#metrics-and-monitoring) for what to alert on.

There is no Prometheus scrape endpoint; this is OTel-only.

## Upgrade

```sh
# Edit .env to set the new EDR_VERSION.
docker compose -f docker-compose.prod.yml --env-file .env pull server
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

MySQL is not recreated on upgrade; its volume persists. Schema changes ship as versioned, forward-only goose migrations that the server applies at boot (see [ADR-0009](adr/0009-migrations-via-goose.md)); an already-applied corpus is a no-op, so re-running an upgrade is safe. For a zero-downtime upgrade of the multi-replica topology, follow the [rolling upgrade](operations.md#rolling-upgrade-multi-replica) runbook.

## Rotate secrets

**Enroll secret**:

```sh
NEW_ENROLL_SECRET=$(openssl rand -hex 32)
printf '%s' "$NEW_ENROLL_SECRET" > secrets/enroll_secret
docker compose -f docker-compose.prod.yml --env-file .env restart server
```

Existing agents keep working because they authenticate with the per-host token they got at enrollment, not the enroll secret. Push the new value to your MDM install-script so the next Mac to enroll uses it.

`kill -s HUP` does NOT rotate the enroll secret; only the TLS cert. Use `docker compose restart server`.

**TLS cert**:

Drop replacement `fullchain.pem` + `privkey.pem` into `./tls/` and send the server a SIGHUP:

```sh
docker compose -f docker-compose.prod.yml --env-file .env kill -s HUP server
```

Active connections are not dropped; new handshakes pick up the new cert.

**MySQL root password**:

```sh
NEW_MYSQL_PASS=$(openssl rand -hex 24)
printf '%s' "$NEW_MYSQL_PASS" > secrets/mysql_root
printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$NEW_MYSQL_PASS" > secrets/edr_dsn
docker compose -f docker-compose.prod.yml --env-file .env up -d --force-recreate mysql server
```

The named volume persists across recreate so no data loss.

## Backup

The entire state fits in the MySQL volume.

```sh
# Live logical backup (safe on InnoDB):
docker compose -f docker-compose.prod.yml exec -T mysql \
    mysqldump --single-transaction -uroot -p"$(cat secrets/mysql_root)" edr \
    | gzip > "edr-$(date +%Y%m%d).sql.gz"
```

Restore into a fresh server:

```sh
gunzip -c edr-YYYYMMDD.sql.gz \
    | docker compose -f docker-compose.prod.yml exec -T mysql \
      mysql -uroot -p"$(cat secrets/mysql_root)" edr
```

Test your restore path quarterly.

## Troubleshoot

**"unknown database 'edr'"** at server startup: MySQL booted but didn't create the `edr` schema. The compose file sets `MYSQL_DATABASE: edr` so this means MySQL initialized earlier without that var set (an earlier compose file shipped without it) and its volume persisted.

```sh
docker compose -f docker-compose.prod.yml exec mysql \
    mysql -uroot -p"$(cat secrets/mysql_root)" \
    -e "CREATE DATABASE IF NOT EXISTS edr;"
docker compose -f docker-compose.prod.yml restart server
```

**Server keeps exiting with "EDR_DSN is required"**: the `edr_dsn` secret file is missing or unreadable. Re-run the secrets step in Setup.

**Server exits with "EDR_TLS_CERT_FILE and EDR_TLS_KEY_FILE are both required"**: either cert path is unset or unreadable. The server has no unguarded plaintext-HTTP mode (issue #140); mount fullchain.pem + privkey.pem under `./tls/` and re-export the `EDR_TLS_CERT_FILE` / `EDR_TLS_KEY_FILE` env vars before retrying. (Behind a TLS-terminating proxy that cannot present a backend cert, set `EDR_TLS_TERMINATED_BY_PROXY=1` and omit the cert files instead.)

**Agents see "enrollment failed: unauthorized"**: the `enroll_secret` on the server and the `EDR_ENROLL_SECRET` the agent reads from `/etc/fleet-edr.conf` are different. Confirm the MDM install-script writes the exact value from `secrets/enroll_secret`.

**Server log shows "exporter export timeout"**: OTel collector is unreachable. Either fix connectivity to `OTEL_EXPORTER_OTLP_ENDPOINT` or unset the var. Server functionality is unaffected; only telemetry is dropped.
