# Fleet EDR server: docker-compose quickstart

This stack runs the fleet-edr-server + MySQL on a single host. It's the
simplest way to stand up the server for a pilot deployment of 10-500 agents.
For larger fleets, use this as the starting shape and split MySQL onto its
own instance.

## One-time setup

```sh
# 1. Pin a released version. `latest` works for dev but is not safe for prod
#    because image digests drift silently.
echo 'EDR_VERSION=v0.5.0' > .env
echo 'OTEL_EXPORTER_OTLP_ENDPOINT=http://host.docker.internal:4317' >> .env

# 2. Generate two secret files. The MySQL root password + the full DSN that
#    embeds it must stay in sync. This is the one awkward edge of using
#    distroless (no shell in the server image, so we cannot derive the DSN
#    at runtime from the root-password secret).
mkdir -p secrets tls
MYSQL_PASS=$(openssl rand -hex 24)
printf '%s' "$MYSQL_PASS" > secrets/mysql_root
printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$MYSQL_PASS" > secrets/edr_dsn
printf 'pilot-enroll-secret-rotate-me' > secrets/enroll_secret
chmod 0600 secrets/*

# 3. TLS. Either put fullchain.pem + privkey.pem under ./tls (Let's Encrypt
#    output via certbot works directly), or opt into insecure HTTP for dev
#    only:
#      echo 'EDR_ALLOW_INSECURE_HTTP=1' >> .env

docker compose -f docker-compose.prod.yml --env-file .env up -d
```

## Verify

```sh
# TLS-enabled deployments (default):
curl -sk https://localhost:8088/readyz | jq .
# For EDR_ALLOW_INSECURE_HTTP=1 dev deployments, use http:// instead:
curl -s http://localhost:8088/readyz | jq .
# {"status":"ok","checks":{"db":{"status":"ok","latency_ms":N}}}
```

Seeded admin email + password are printed once on server boot: `docker compose
-f docker-compose.prod.yml --env-file .env logs server | head -20`.

## Upgrade

```sh
# Edit .env to set the new EDR_VERSION.
docker compose -f docker-compose.prod.yml --env-file .env pull server
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

No DB migration needed within the v0.5.x series; schema is `CREATE TABLE IF
NOT EXISTS` throughout.

## Secret rotation

**Enroll secret**. Overwrite `secrets/enroll_secret` with the new value and
restart the server so it re-reads the secret file:

```sh
docker compose -f docker-compose.prod.yml --env-file .env restart server
```

Existing per-host tokens are not affected by enroll-secret rotation because
they were derived at enroll time, not re-verified against the secret on
every auth. SIGHUP is NOT wired for secret reload; only TLS cert reload
responds to it.

**MySQL root password**. Overwrite both `secrets/mysql_root` and
`secrets/edr_dsn` with the new password, then `docker compose up -d
--force-recreate mysql server`. The volume data persists across recreates.

**TLS cert**. Drop new `tls/fullchain.pem` + `tls/privkey.pem`. The server
watches SIGHUP for TLS reload; `docker compose kill -s HUP server` swaps
the cert without dropping active connections.

## OTel metrics + logs

Set `OTEL_EXPORTER_OTLP_ENDPOINT` in `.env` to your SigNoz / collector
endpoint. The server emits:

- Traces for every HTTP request + DB query.
- Logs via `otelslog` with `service.name=fleet-edr-server`.
- Metrics listed in `claude/mvp/phase-4-lifecycle-observability.md`.

There is no Prometheus scrape endpoint.

## Known limits

- Single MySQL instance; no replicas. For pilots ≤500 agents this is fine.
- No horizontal scaling of the server instance yet. A second replica would
  need a shared enroll-secret rotation mechanism (currently each replica
  reads its own secret file) and a sticky session or shared cookie store.
  Phase 7+ consideration.
- No automatic backup of `edr-mysql-data`. Operators run their own
  `mysqldump` or volume snapshot schedule.
