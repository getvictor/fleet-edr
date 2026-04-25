# Day-2 operations

This is the runbook for operating a Fleet EDR server + agent fleet
that's already deployed. If you're setting it up for the first time,
start with [install-server.md](install-server.md) and
[mdm-deployment.md](mdm-deployment.md).

## Quick reference

| Task | Command |
|---|---|
| Server health | `curl -s https://<server>/readyz \| jq .` |
| Server version | `curl -s https://<server>/readyz \| jq -r .version` |
| Tail server log | `docker compose logs -f server` |
| Tail agent log (on Mac) | `sudo tail -f /var/log/fleet-edr-agent.log` |
| Agent state (on Mac) | `sudo launchctl print system/com.fleetdm.edr.agent` |
| Reload TLS cert | `docker compose kill -s HUP server` |
| Restart server | `docker compose restart server` |
| Backup DB | `docker compose exec -T mysql mysqldump --single-transaction -uroot -p"$(cat secrets/mysql_root)" edr \| gzip > edr-$(date +%F).sql.gz` |

The `curl` examples below verify the server's TLS certificate. If you
deploy with a self-signed cert (lab / air-gapped pilot), either add
the CA to the machine's trust store or pass `--cacert /path/to/ca.pem`
rather than bypassing verification with `-k`.

## Upgrade the server

Server releases are tagged images at
`ghcr.io/getvictor/fleet-edr-server:<version>` and new pkg / profile
bundles on the GitHub Releases page. Server + agent versions are
independent; upgrade them on separate schedules.

```sh
# 1. Decide on the version. Use the exact tag from the releases page;
#    do not use :latest in production.
# 2. Edit /srv/fleet-edr/.env and bump EDR_VERSION.
# 3. Pull the new image and restart.
cd /srv/fleet-edr
docker compose -f docker-compose.prod.yml --env-file .env pull server
docker compose -f docker-compose.prod.yml --env-file .env up -d

# 4. Verify.
curl -s https://<server>/readyz | jq .
```

There is no downtime tolerated by MySQL during this. The server
container restarts in place; MySQL keeps running. Expect ~2s of
HTTP 503 while the new server boots; agents retry automatically.

DDL in the v0.1.x line is `CREATE TABLE IF NOT EXISTS` throughout, so
minor upgrades don't require a MySQL migration. Major-version upgrades
will ship with a migration runbook in the release notes.

## Upgrade agents

Agents upgrade by pushing a newer `.pkg` through your MDM. See your
MDM's section in [mdm-deployment.md](mdm-deployment.md); for Fleet, see
[fleet-deployment.md](fleet-deployment.md).

Never hand-install a newer pkg on a single MDM-managed Mac to "test
the upgrade path". The MDM will re-deploy the old version on the next
sync and you'll waste time debugging a drift you caused.

Validate a handful of Macs before rolling fleet-wide:

1. Scope the new pkg to a small canary team (5-10 Macs).
2. Wait 24h. Check the EDR admin UI: all canary hosts back online,
   `last_seen` fresh, no alert spike.
3. Re-scope to the full fleet.

## Rotate secrets

### Enroll secret

The enroll secret is shared between the server and the install script
your MDM runs. Rotate it when you suspect it's leaked (committed to
a public repo, shared over an insecure channel). Existing agents are
unaffected — they authenticate with their per-host token.

```sh
cd /srv/fleet-edr
NEW_ENROLL_SECRET=$(openssl rand -hex 32)
printf '%s' "$NEW_ENROLL_SECRET" > secrets/enroll_secret
docker compose -f docker-compose.prod.yml --env-file .env restart server
```

Then update your MDM's secret variable (see your vendor's section in
[mdm-deployment.md](mdm-deployment.md)) so freshly-enrolled Macs pick
up the new value.

Important: `docker compose kill -s HUP server` does NOT rotate the
enroll secret. SIGHUP is TLS-only. Use `restart`.

### TLS cert

```sh
# Drop the new cert and key alongside the old ones.
sudo cp /etc/letsencrypt/live/edr.example.com/fullchain.pem /srv/fleet-edr/tls/
sudo cp /etc/letsencrypt/live/edr.example.com/privkey.pem /srv/fleet-edr/tls/
sudo chmod 0644 /srv/fleet-edr/tls/fullchain.pem
sudo chmod 0600 /srv/fleet-edr/tls/privkey.pem

# Tell the running server to re-read them.
docker compose -f docker-compose.prod.yml --env-file .env kill -s HUP server
```

Active TLS connections stay up. New handshakes pick up the new cert on
the next `ClientHello`. Verify with:

```sh
openssl s_client -connect <server>:443 -servername <server> </dev/null 2>/dev/null \
    | openssl x509 -noout -dates
```

Wire this into your Let's Encrypt renewal hook so it happens
automatically on renewal.

### MySQL root password

Less common (MySQL isn't exposed outside the Compose network), but:

```sh
cd /srv/fleet-edr
NEW_MYSQL_PASS=$(openssl rand -hex 24)
printf '%s' "$NEW_MYSQL_PASS" > secrets/mysql_root
printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$NEW_MYSQL_PASS" > secrets/edr_dsn
docker compose -f docker-compose.prod.yml --env-file .env up -d --force-recreate mysql server
```

The named volume persists across recreate; no data loss. The server
restarts once mysql is ready (Compose healthcheck gates it).

## Backup and restore

The entire EDR state is in the MySQL `edr` schema. The named volume
`mysql-data` is the source of truth; nothing else is stateful.

### Logical backup

```sh
docker compose -f docker-compose.prod.yml exec -T mysql \
    mysqldump --single-transaction --routines --triggers \
    -uroot -p"$(cat secrets/mysql_root)" edr \
    | gzip > "edr-$(date +%Y%m%d).sql.gz"
```

`--single-transaction` works because every EDR table is InnoDB, so the
backup doesn't block writes.

Ship the `.sql.gz` off-host (S3, Backblaze B2, borg, whatever your
standard is). Keep at least 30 days, longer if your compliance regime
says so.

### Restore

Spin up a fresh server stack with empty volumes, then:

```sh
gunzip -c edr-YYYYMMDD.sql.gz \
    | docker compose -f docker-compose.prod.yml exec -T mysql \
      mysql -uroot -p"$(cat secrets/mysql_root)" edr
```

The agents' persisted host tokens keep working after a restore — the
`hosts` table survives, so enrollments don't churn. Expect the
`last_seen` gauge to tick back to current within ~30s as agents
reconnect.

Test your restore path quarterly. An untested backup is a hope, not a
backup.

### Volume snapshots

If your host filesystem is ZFS / Btrfs / LVM-thin, volume snapshots are
faster than logical backups. Point-in-time recovery via binlog replay
is not supported in v0.1 because the server doesn't emit binlogs by
default; rely on logical backups + snapshots for now.

## Retention tuning

The server deletes events older than `EDR_RETENTION_DAYS` (default 30)
on a schedule set by `EDR_RETENTION_INTERVAL` (default 1h). Both knobs
live in the server's environment; restart to take effect.

Three common scenarios:

1. **Compliance requires 90 days of event history.**
   Set `EDR_RETENTION_DAYS=90`. Monitor `edr.retention.rows_deleted`
   and the DB disk usage for a week to confirm storage is sized right.
2. **Disk is filling up, want to shrink window.**
   Set a smaller `EDR_RETENTION_DAYS` value. The next retention run
   will delete events older than the new cutoff. Expect one large
   deletion, then normal churn.
3. **Want to keep events forever for a forensic investigation.**
   Set `EDR_RETENTION_DAYS=0`. Retention is disabled. Re-enable once
   the investigation is complete to avoid unbounded growth.

Alerts are NOT deleted by retention. They stay until you delete them
via the admin UI. A resolved alert pointing at an event that retention
has purged will still render, with the event references 404ing.

## Metrics and monitoring

Server exports OpenTelemetry metrics via OTLP/gRPC to the endpoint in
`OTEL_EXPORTER_OTLP_ENDPOINT`. No Prometheus scrape endpoint is
provided. See [install-server.md](install-server.md#otel-metrics-and-logs).

Core metrics to chart:

| Metric | Type | What to watch |
|---|---|---|
| `edr.events.ingested` | counter | Spikes up = agent fleet healthy. Drop to zero = ingress wedged |
| `edr.alerts.created` | counter | By `rule_id` + `severity`. Sudden spike warrants a look |
| `edr.enrolled.hosts` | gauge | Should match your MDM's scoped Mac count |
| `edr.offline.hosts` | gauge | Hosts whose `last_seen` is older than 5 min. Keep near zero |
| `edr.retention.rows_deleted` | counter | Should tick up every `EDR_RETENTION_INTERVAL` |
| `edr.db.query.duration` | histogram | p99 creeping up = DB overloaded or a slow query regressed |
| `edr.agent.queue.dropped` | counter | Non-zero = agent's local SQLite queue hit its cap. Investigate connectivity |
| `edr.policy.fanout_failed` | counter | Policy updates that failed to reach at least one host |

Recommended alerts (SigNoz, Grafana, wherever your OTel backend lives):

- `edr.offline.hosts > 10% of edr.enrolled.hosts for 15m` — fleet-wide
  connectivity issue.
- `rate(edr.events.ingested[5m]) == 0 for 5m` — server isn't receiving
  events. Either all agents are offline (see above), ingress is
  broken, or the server wedged.
- `rate(edr.retention.rows_deleted[1h]) == 0 for 2h` when
  `EDR_RETENTION_DAYS > 0` — retention job stuck.
- `rate(edr.agent.queue.dropped[5m]) > 0` — endpoints losing data.

Server logs go through the same OTLP pipeline (via `otelslog`) with
`service.name=fleet-edr-server`. Use them for audit-style queries like
"who resolved alert X" (look for `edr.admin.action=alert_update` log
events with `user.id`).

## Handling offline hosts

A host is "offline" when the server hasn't heard from it in >5 min.
The admin UI tags these rows with a red dot.

Common causes, in order:

1. **Endpoint is powered off / asleep.** Nothing to do; the host
   reconnects on next wake.
2. **Network-level change.** Moved to a VPN / Wi-Fi with egress
   filtering. Validate `curl -v https://<edr-server>/livez` from the
   endpoint.
3. **Agent crashed.**
   `sudo launchctl print system/com.fleetdm.edr.agent` shows `state =
   running`? If not:
   `sudo launchctl kickstart -k system/com.fleetdm.edr.agent`.
4. **Enrollment revoked.** Check
   `POST /api/v1/admin/enrollments/{host_id}/revoke` logs. Re-enroll
   by re-running the MDM install-script and restarting the daemon.
5. **DB clock skew / server down.** `edr.enrolled.hosts` gauge
   returning -1 means the DB query failed.

If a host has been offline for >30 days and you expect it to be
permanently gone (retired laptop), revoke the enrollment from the UI
(`Hosts > <host> > Revoke enrollment`) so its host-token can no longer
be used.

## Managing the blocklist (policy)

The blocklist is a server-driven policy pushed to every enrolled host
via the command queue. One policy per server; all hosts see the same
list.

```sh
# View current policy.
curl -s -b cookies.txt https://<server>/api/v1/admin/policy | jq .

# Update policy (requires login + CSRF token).
# Easier via the admin UI: Settings > Policy > Blocklist.
```

The policy has two fields:

- `blocklist.paths` — absolute paths. Any exec() with an `argv[0]` or
  resolved executable path matching the list triggers an alert and
  (for the sysext) kills the process before it executes.
- `blocklist.hashes` — SHA-256 of the binary. Same behavior, matched
  on digest.

The `EDR_LAUNCHAGENT_ALLOWLIST` env var is different: it tells the
server's `persistence_launchagent` detection rule which LaunchAgent
paths are benign and should not trigger alerts. Set it as a
comma-separated list of absolute paths.

`EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST` is the parallel knob for the
`privilege_launchd_plist_write` rule. Apple-signed platform binaries
(installd, system_installd, ...) are always allowed; this list is for
non-Apple agents that legitimately drop daemons under
`/Library/LaunchDaemons/` (Munki, Kandji, JumpCloud, etc.). Set it as
a comma-separated list of code-signing team IDs, e.g.
`T4SK8ZXCXG,XYZW0KL1Q9`.

`EDR_SUDOERS_WRITER_ALLOWLIST` is the parallel knob for the
`sudoers_tamper` rule. Direct writes to `/etc/sudoers` or
`/etc/sudoers.d/*` always fire unless the writing process's path is
on this list. visudo / sudoedit don't need to be allowlisted — they
write a temp file and atomically rename it, so the rule never sees
their open events. The typical use case is allowlisting an MDM
agent's binary path. Set it as a comma-separated list of absolute
paths, e.g. `/usr/local/bin/munki-managed-installer`.

## Common troubleshooting

**Readyz says `db: error`.**
MySQL unreachable. Check `docker compose ps` and
`docker compose logs mysql`. Restart the stack if MySQL is stuck in a
restart loop.

**Server log: `exporter export timeout`.**
OTel collector unreachable. Fix connectivity to
`OTEL_EXPORTER_OTLP_ENDPOINT` or unset the var to disable metrics
export. Server functionality is unaffected; only telemetry is dropped.

**Admin UI shows a host but `last_seen` is stuck >30 min ago.**
Either the host is offline (see above) or its agent is running but
failing to post events. SSH to the host, tail
`/var/log/fleet-edr-agent.log`; expect TLS / network / 401 errors if
the agent is failing to reach the server.

**Alerts appear for a binary you know is benign.**
Add its path to `EDR_LAUNCHAGENT_ALLOWLIST` (if it's a LaunchAgent),
or add an allow rule in the UI for the rule that fired. Mark the
existing alerts as `resolved` once you've confirmed they're false
positives.

**All agents went offline at once.**
Check the EDR server first (`/readyz`), then your ingress / LB, then
your TLS cert's expiry. If the cert expired, see "Rotate secrets >
TLS cert" above; agents will reconnect once the cert is fixed without
needing a restart on their end.

**MySQL disk is full.**
Shrink `EDR_RETENTION_DAYS`, restart the server, wait for one
retention run. If that isn't enough, the events table is larger than
your disk; you need either more disk or a shorter window. There is no
online rebalance — expand storage and restart.

**`docker compose up -d` fails with `volume mysql-data is in use`.**
A previous server process didn't shut down cleanly. `docker compose
down && docker compose up -d` usually clears it. Do NOT
`docker volume rm mysql-data`; that wipes the database.
