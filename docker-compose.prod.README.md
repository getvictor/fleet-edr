# Fleet EDR server: docker-compose quickstart

This stack runs the fleet-edr-server + MySQL on a single host. It's the simplest way to stand up the server for a pilot deployment of 10-500 agents. For larger fleets, use this as the starting shape and split MySQL onto its own instance.

## One-time setup

```sh
# 1. Pin a released version. `latest` works for dev but is not safe for prod
#    because image digests drift silently.
echo 'EDR_VERSION=v0.3.0' > .env
echo 'OTEL_EXPORTER_OTLP_ENDPOINT=http://host.docker.internal:4317' >> .env

# 2. Generate the secret files. The MySQL root password + the full DSN that
#    embeds it must stay in sync. This is the one awkward edge of using
#    distroless (no shell in the server image, so we cannot derive the DSN
#    at runtime from the root-password secret). secret_key is the deployment
#    root secret (>=32 bytes); the server derives the host-token HMAC pepper and
#    other long-lived keys from it and refuses to boot without it. Changing it
#    later invalidates every enrolled host, so back it up.
mkdir -p secrets tls
# 0700 on the directory keeps the world-readable (0644) secret files below it
# unreadable to other local users: a 0700 dir blocks non-owners from traversing
# in, while the Docker daemon (root) still reads the files to bind-mount them.
chmod 0700 secrets
MYSQL_PASS=$(openssl rand -hex 24)
printf '%s' "$MYSQL_PASS" > secrets/mysql_root
printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$MYSQL_PASS" > secrets/edr_dsn
printf '%s' "$(openssl rand -hex 32)" > secrets/secret_key
printf 'pilot-enroll-secret-rotate-me' > secrets/enroll_secret
# 0644, not 0600: Compose bind-mounts a file secret with the host file's owner
# and mode (the uid/gid/mode long-syntax options are Swarm only), and the server
# image runs as nonroot, so a 0600 file owned by your shell user is unreadable
# inside the container and the server crash-loops on "permission denied". The
# value still never lands in `docker inspect`, the process environment, or an
# image layer, which is the point of using a file secret.
chmod 0644 secrets/*

# 3. TLS. Put fullchain.pem + privkey.pem under ./tls (Let's Encrypt output via
#    certbot works directly). TLS is unconditionally required; the server
#    refuses to boot when either cert path is unreadable.

docker compose -f docker-compose.prod.yml up -d
```

## Verify

```sh
curl -sk https://localhost:8088/readyz | jq .
# {"status":"ok","checks":{"db":{"status":"ok","latency_ms":N}}}
```

`-k` bypasses cert verification for the local self-signed probe; production automation against a real Let's Encrypt-issued cert should drop it.

The first-boot break-glass redemption URL prints to stderr until the admin redeems it; capture with `docker compose -f docker-compose.prod.yml logs server | grep -B 1 -A 4 BREAK-GLASS`. Open the URL in a browser within the TTL (default 1h) to set a password and register a WebAuthn credential. See [`docs/install-server.md`](docs/install-server.md) for the full first-boot flow.

## Upgrade

```sh
# Edit .env to set the new EDR_VERSION.
docker compose -f docker-compose.prod.yml pull server
docker compose -f docker-compose.prod.yml up -d
```

No DB migration needed within the v0.1.x series; schema is `CREATE TABLE IF NOT EXISTS` throughout.

## Secret rotation

**Enroll secret**. Overwrite `secrets/enroll_secret` with the new value and restart the server so it re-reads the secret file:

```sh
docker compose -f docker-compose.prod.yml restart server
```

Existing per-host tokens are not affected by enroll-secret rotation because they were derived at enroll time, not re-verified against the secret on every auth. SIGHUP is NOT wired for secret reload; only TLS cert reload responds to it.

**MySQL root password**. Overwrite both `secrets/mysql_root` and `secrets/edr_dsn` with the new password, then `docker compose up -d --force-recreate mysql server`. The volume data persists across recreates.

**Deployment secret key** (`secrets/secret_key`). Treat this as un-rotatable in normal operation: every host token derives from it, so overwriting it invalidates every enrolled host and forces a fleet-wide re-enroll. Back it up rather than rotating it.

**TLS cert**. Drop new `tls/fullchain.pem` + `tls/privkey.pem`. The server watches SIGHUP for TLS reload; `docker compose kill -s HUP server` swaps the cert without dropping active connections.

## OTel metrics + logs

Set `OTEL_EXPORTER_OTLP_ENDPOINT` in `.env` to your SigNoz / collector endpoint. The server emits:

- Traces for every HTTP request + DB query.
- Logs via `otelslog` with `service.name=fleet-edr-server`.
- Metrics: `edr.events.ingested`, `edr.alerts.created`, `edr.enrolled.hosts`, `edr.offline.hosts`, `edr.retention.rows_deleted`, `edr.db.query.duration`, `edr.agent.queue.dropped`. See [docs/install-server.md](docs/install-server.md#otel-metrics-and-logs) for the full list and [docs/operations.md](docs/operations.md#metrics-and-monitoring) for what to alert on.

There is no Prometheus scrape endpoint.

## Known limits

- Single MySQL instance; no replicas. For pilots ≤500 agents this is fine.
- No horizontal scaling of the server instance yet. A second replica would need a shared enroll-secret rotation mechanism (currently each replica reads its own secret file) and a sticky session or shared cookie store. Tracked as future work for the post-MVP scaling story.
- No automatic backup of `edr-mysql-data`. Operators run their own `mysqldump` or volume snapshot schedule.
