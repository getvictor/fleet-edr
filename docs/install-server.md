# Install the Fleet EDR server

The reference deployment is Docker Compose: MySQL + the server image,
with a TLS-terminating ingress in front. The stack is sized for a single
customer with 10 to 500 endpoints. Larger fleets should split MySQL onto
its own instance and run the server image behind a load balancer, using
this setup as the starting shape.

## Prerequisites

- A Linux host with Docker Engine 24+ and Docker Compose v2 (`docker
  compose`, not `docker-compose`).
- 4 GB RAM, 2 CPU cores, 20 GB disk.
- A hostname + TLS certificate (see "TLS setup" below), or an intention
  to run without TLS for a lab.
- Inbound TCP to the server's ingress (default port 8088). Outbound to
  nothing except your OTel collector if you enable metrics.

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

### 3. Create secret files

Three secret files live under `./secrets/` with mode 0600. Docker Compose
bind-mounts them into the server + mysql containers as
`/run/secrets/<name>`. None of the values land in any env block or
`docker inspect` output.

```sh
mkdir -p secrets
MYSQL_PASS=$(openssl rand -hex 24)
printf '%s' "$MYSQL_PASS" > secrets/mysql_root
printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$MYSQL_PASS" > secrets/edr_dsn
ENROLL_SECRET=$(openssl rand -hex 32)
printf '%s' "$ENROLL_SECRET" > secrets/enroll_secret
chmod 0600 secrets/*
```

The `edr_dsn` file contains the same MySQL password embedded into a Go
DSN. The server reads it via the `EDR_DSN_FILE` pattern (see
`server/config/file_env.go`) so the password never appears in a compose
env block.

Keep `MYSQL_PASS` and `ENROLL_SECRET` somewhere safe. You'll paste
`ENROLL_SECRET` into your MDM install-script config when you deploy
agents.

### 4. TLS setup

Two options.

**Option A: let the server terminate TLS.**
Drop `fullchain.pem` + `privkey.pem` into `./tls/` (certbot output works
directly). The compose bind-mounts `./tls` read-only into the server
container.

```sh
mkdir -p tls
cp /etc/letsencrypt/live/edr.example.com/fullchain.pem tls/
cp /etc/letsencrypt/live/edr.example.com/privkey.pem tls/
chmod 0644 tls/fullchain.pem
chmod 0600 tls/privkey.pem
```

In your `.env` (next step), set:

```
EDR_TLS_CERT_FILE=/tls/fullchain.pem
EDR_TLS_KEY_FILE=/tls/privkey.pem
```

**Option B: terminate TLS upstream (nginx, Caddy, an ALB, Cloudflare Tunnel).**
The server runs in plaintext HTTP on 8088 inside the compose network; your
upstream handles TLS. Set:

```
EDR_ALLOW_INSECURE_HTTP=1
```

Never set that flag on an internet-exposed server that isn't behind a
TLS-terminating proxy. The agent refuses `http://` URLs unless its own
`EDR_ALLOW_INSECURE` flag is also set, so a misconfigured customer would
fail closed rather than silently deploy unencrypted telemetry.

### 5. Pin a version in .env

```sh
cat > .env <<'EOF'
EDR_VERSION=v0.1.0
OTEL_EXPORTER_OTLP_ENDPOINT=
EOF
```

Use the exact tag from the [Releases page](https://github.com/getvictor/fleet-edr/releases).
`latest` is fine for a lab but unsafe for a pilot because the digest
drifts silently on each release.

### 6. Boot the stack

```sh
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

MySQL starts first (healthcheck gates the server), then the server image
pulls from ghcr.io and comes up.

## Verify

### Readiness probe

TLS-terminated deployment:

```sh
curl -s https://edr.example.com/readyz | jq .
```

If you're running with a self-signed cert (lab / air-gapped pilot),
either add the CA to the local trust store, pass
`--cacert /path/to/ca.pem`, or temporarily use `-k` for this probe.
Don't paper over a trust failure with `-k` in an automation script.

Insecure-HTTP deployment (dev / behind-proxy):

```sh
curl -s http://localhost:8088/readyz | jq .
```

Expect:

```json
{
  "status": "ok",
  "version": "v0.1.0",
  "uptime_seconds": 12,
  "checks": {
    "db": {"status": "ok", "latency_ms": 2}
  }
}
```

If `db.status` is `error` / `unavailable`, MySQL isn't reachable. Check
`docker compose logs mysql`.

### Capture the admin password

The server seeds a single admin account on first boot. The password
prints to the log exactly once:

```sh
docker compose -f docker-compose.prod.yml --env-file .env logs server \
    | grep -A 1 SEEDED
```

Expected output:

```
================================================================
SEEDED ADMIN USER (captured once — save the password now)
  Email:    admin@fleet-edr.local
  Password: <random>
================================================================
```

Paste the password into your secret store. If you miss it you have to
stop the server, delete the admin row from MySQL, and restart to
re-seed. Don't lose it.

### Log into the UI

Open `https://edr.example.com/ui/` (or `http://localhost:8088/ui/` in
dev). Sign in with `admin@fleet-edr.local` + the password above. The
hosts page should be empty; that changes when the first agent enrolls.

## Configuration reference

Non-exhaustive; see `server/config/config.go` for every knob. Anything
unset uses the documented default.

| Env var | Required | Default | Purpose |
|---|---|---|---|
| `EDR_DSN` / `EDR_DSN_FILE` | yes | — | MySQL DSN, `user:pass@tcp(host:port)/db?parseTime=true` |
| `EDR_ENROLL_SECRET` / `EDR_ENROLL_SECRET_FILE` | yes | — | Shared secret agents present at enrollment |
| `EDR_LISTEN_ADDR` | no | `:8088` | TCP address the HTTP server binds |
| `EDR_TLS_CERT_FILE` | no | — | PEM cert for TLS termination (pair with key) |
| `EDR_TLS_KEY_FILE` | no | — | PEM key (pair with cert) |
| `EDR_ALLOW_INSECURE_HTTP` | no | 0 | Set to `1` to skip TLS (only behind an upstream terminator) |
| `EDR_TLS_ALLOW_TLS12` | no | 0 | Allow TLS 1.2 (default is 1.3-only) |
| `EDR_ENROLL_RATE_PER_MIN` | no | 30 | Per-IP enroll rate limit |
| `EDR_LOGIN_RATE_PER_MIN` | no | 6 | Per-IP UI login rate limit |
| `EDR_RETENTION_DAYS` | no | 30 | Event TTL, 0 disables retention |
| `EDR_RETENTION_INTERVAL` | no | 1h | How often the retention job runs |
| `EDR_LAUNCHAGENT_ALLOWLIST` | no | — | Comma-separated absolute paths the `persistence_launchagent` rule treats as benign |
| `EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST` | no | — | Comma-separated code-signing team IDs the `privilege_launchd_plist_write` rule treats as benign |
| `EDR_SUDOERS_WRITER_ALLOWLIST` | no | — | Comma-separated writer-process absolute paths the `sudoers_tamper` rule treats as benign; alerts may surface either `/etc/sudoers...` or `/private/etc/sudoers...` because `/etc` is a symlink and ES reports the path as opened |
| `EDR_LOG_LEVEL` | no | info | `debug` / `info` / `warn` / `error` |
| `EDR_LOG_FORMAT` | no | json | `json` or `text` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | — | `host:port` of an OTLP/gRPC collector; unset disables metrics export |

Every string knob accepts a `_FILE` variant (`EDR_ENROLL_SECRET_FILE`,
`EDR_DSN_FILE`, etc.) that points at a file whose trimmed contents
become the value. That's how the compose stack delivers secrets.

## OTel metrics and logs

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to your collector (SigNoz, Tempo,
Datadog OTel, etc.). The server exports:

- **Traces** for every HTTP request + DB query.
- **Logs** via `otelslog` with `service.name=fleet-edr-server`.
- **Metrics**:
  - `edr.events.ingested` (counter, by `host_id`) — accepted events.
  - `edr.alerts.created` (counter, by `rule_id` + `severity`).
  - `edr.enrolled.hosts` (gauge) — current enrolled count.
  - `edr.offline.hosts` (gauge) — hosts unseen >5 min.
  - `edr.retention.rows_deleted` (counter) — rows pruned per run.
  - `edr.db.query.duration` (histogram, by `op`).
  - `edr.agent.queue.dropped` (counter) — agent-side drops reported back.

  See [operations.md](operations.md#metrics-and-monitoring) for what to
  alert on.

There is no Prometheus scrape endpoint; this is OTel-only.

## Upgrade

```sh
# Edit .env to set the new EDR_VERSION.
docker compose -f docker-compose.prod.yml --env-file .env pull server
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

MySQL is not recreated on upgrade; its volume persists. No schema
migration needed within the v0.1.x series because the DDL is
`CREATE TABLE IF NOT EXISTS` throughout.

## Rotate secrets

**Enroll secret**:

```sh
NEW_ENROLL_SECRET=$(openssl rand -hex 32)
printf '%s' "$NEW_ENROLL_SECRET" > secrets/enroll_secret
docker compose -f docker-compose.prod.yml --env-file .env restart server
```

Existing agents keep working because they authenticate with the per-host
token they got at enrollment, not the enroll secret. Push the new value
to your MDM install-script so the next Mac to enroll uses it.

`kill -s HUP` does NOT rotate the enroll secret; only the TLS cert. Use
`docker compose restart server`.

**TLS cert**:

Drop replacement `fullchain.pem` + `privkey.pem` into `./tls/` and send
the server a SIGHUP:

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

**"unknown database 'edr'"** at server startup — MySQL booted but
didn't create the `edr` schema. The compose file sets
`MYSQL_DATABASE: edr` so this means MySQL initialized earlier without
that var set (pre-Phase-5 behavior) and its volume persisted.

```sh
docker compose -f docker-compose.prod.yml exec mysql \
    mysql -uroot -p"$(cat secrets/mysql_root)" \
    -e "CREATE DATABASE IF NOT EXISTS edr;"
docker compose -f docker-compose.prod.yml restart server
```

**Server keeps exiting with "EDR_DSN is required"** — the `edr_dsn`
secret file is missing or unreadable. Re-run the secrets step in Setup.

**Server exits with "EDR_TLS_CERT_FILE is required"** — you're running
without TLS and forgot `EDR_ALLOW_INSECURE_HTTP=1`. Either provide a
cert+key or set the flag.

**Agents see "enrollment failed: unauthorized"** — the `enroll_secret`
on the server and the `EDR_ENROLL_SECRET` the agent reads from
`/etc/fleet-edr.conf` are different. Confirm the MDM install-script
writes the exact value from `secrets/enroll_secret`.

**Server log shows "exporter export timeout"** — OTel collector is
unreachable. Either fix connectivity to `OTEL_EXPORTER_OTLP_ENDPOINT`
or unset the var. Server functionality is unaffected; only telemetry
is dropped.
