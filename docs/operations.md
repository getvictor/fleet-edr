# Day-2 operations

This is the runbook for operating a Fleet EDR server + agent fleet that's already deployed. If you're setting it up for the first time, start with [install-server.md](install-server.md) and [mdm-deployment.md](mdm-deployment.md).

## Quick reference

| Task | Command |
| --- | --- |
| Server health | `curl -s https://<server>/readyz \| jq .` |
| Server version | `curl -s https://<server>/readyz \| jq -r .version` |
| Tail server log | `docker compose logs -f server` |
| Tail agent log (on Mac) | `sudo tail -f /var/log/fleet-edr-agent.log` |
| Agent state (on Mac) | `sudo launchctl print system/com.fleetdm.edr.agent` |
| Reload TLS cert | `docker compose kill -s HUP server` |
| Restart server | `docker compose restart server` |
| Backup DB | `docker compose exec -T mysql mysqldump --single-transaction -uroot -p"$(cat secrets/mysql_root)" edr \| gzip > edr-$(date +%F).sql.gz` |

The `curl` examples below verify the server's TLS certificate. If you deploy with a self-signed cert (lab / air-gapped pilot), either add the CA to the machine's trust store or pass `--cacert /path/to/ca.pem` rather than bypassing verification with `-k`.

## Upgrade the server

Server releases are tagged images at `ghcr.io/getvictor/fleet-edr-server:<version>` and new pkg / profile bundles on the GitHub Releases page. Server + agent versions are independent; upgrade them on separate schedules.

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

This is the single-replica path: the server container restarts in place, MySQL keeps running, and you accept ~2s of HTTP 503 while the new server boots (agents retry automatically). For a zero-downtime upgrade, run the multi-replica topology and follow [Rolling upgrade](#rolling-upgrade-multi-replica) below instead.

Schema changes ship as versioned, forward-only goose migrations (see [ADR-0009](adr/0009-migrations-via-goose.md)) that the server applies at boot, not as in-process DDL. On upgrade the new server applies any pending migrations against the running MySQL as it starts; an already-applied corpus is a no-op. Migrations follow the expand-contract pattern, so the old and new server versions tolerate the same schema during the swap.

## Rolling upgrade (multi-replica)

This is the zero-downtime upgrade path for the multi-replica topology ([install-server.md](install-server.md#deployment-topology)). It replaces replicas one at a time so the load balancer always has a ready replica to route to. The whole arc that makes it safe is recorded in [ADR-0011](adr/0011-ha-architecture.md).

What makes it hitless, and the piece each part plays:

- **Drain.** On SIGTERM a replica reports `/readyz` 503 for `EDR_SHUTDOWN_DRAIN` (default 30s) before closing its listener, so the LB pulls it from rotation and finishes in-flight requests elsewhere. Set the LB's health-check interval shorter than the drain window so it notices the 503 in time.
- **Migrations.** The first new-version replica to boot applies any pending goose migrations under a MySQL advisory lock; replicas that boot while it holds the lock block briefly, then see an already-applied corpus and no-op. No two replicas ever run the migration tool against the database at once.
- **Stateless tier.** Sessions and CSRF tokens are MySQL-backed, so a logged-in operator whose replica is being replaced is served by another replica with no re-login (no sticky sessions). See [ADR-0010](adr/0010-stateless-server.md).
- **Leader failover.** Retention and the stale-process TTL reconciler run on a single replica via an advisory lock; when that replica is drained the lock frees and another replica takes over on its next poll. The event processor is not coordinated: it scales across every replica via `SKIP LOCKED`.

Procedure:

```sh
# 1. Bump EDR_VERSION in .env to the exact release tag, then pull.
cd /srv/fleet-edr   # the directory holding docker-compose-multi-replica.yml
docker compose -f docker-compose-multi-replica.yml --env-file .env pull

# 2. Recreate one replica at a time. Compose sends SIGTERM (drain), waits, then
#    starts the new container with a fresh IP. Reload the proxy so NGINX
#    re-resolves the upstream IPs (it caches them at start, so a recreated
#    container's new IP would otherwise 502). Then confirm THIS replica is up by
#    reading its own log, not by curling the LB: a /readyz through the LB can be
#    answered by the still-healthy sibling and return a false-positive 200.
docker compose -f docker-compose-multi-replica.yml --env-file .env up -d --no-deps server-a
docker compose -f docker-compose-multi-replica.yml kill -s HUP proxy
docker compose -f docker-compose-multi-replica.yml logs --tail=20 server-a

# Only after server-a's log shows it serving, roll server-b the same way.
docker compose -f docker-compose-multi-replica.yml --env-file .env up -d --no-deps server-b
docker compose -f docker-compose-multi-replica.yml kill -s HUP proxy
docker compose -f docker-compose-multi-replica.yml logs --tail=20 server-b

# 3. Confirm the rolled version through the load balancer. Use the real hostname
#    so TLS verifies (pass --cacert for a private CA, as elsewhere in this
#    runbook); do not normalize -k against a production endpoint.
curl -fsS https://<server>/readyz | jq -r .version
```

Because two binary versions read and write the same MySQL between step 2's two commands, every schema change is expand-contract: a migration only adds columns/tables (or widens) so the older version keeps working against the newer schema. A change that would drop or narrow a column ships across two releases (expand in release N, contract in N+1) so no single rolling upgrade ever has both versions disagreeing on a column's existence.

If a new replica fails to come up (bad image tag), the old replicas stay in rotation: the proxy never routes to a container whose `/readyz` is not green, so the control plane is unaffected. Fix `.env` and re-run. A failed migration is different: MySQL commits DDL implicitly, so a migration that fails partway can leave the schema partially advanced (goose records the version only on full success). Recovery is forward-only per [ADR-0009](adr/0009-migrations-via-goose.md): fix the migration and re-apply, or restore from backup; do not hand-edit the schema.

## Multi-replica trade-offs

The stateless tier ([ADR-0010](adr/0010-stateless-server.md)) accepts two bounded per-replica behaviours rather than adding a second coordination dependency. Both are operational knobs, not bugs.

### Per-IP rate limiting is per replica

The per-source-IP rate limiter (`server/httpserver/iplimiter.go`, in front of the public enroll + login + break-glass routes) keeps its token buckets in process memory, so each replica counts independently. Behind N replicas a single source IP can therefore burst up to N times the per-replica limit before any one replica throttles it, because the LB spreads its requests across the fleet.

Size the per-replica limit with that in mind: divide the fleet-wide budget you want by the replica count. The fragmentation is bounded (it never exceeds N times the limit) and the limiter is a coarse abuse-control measure, not a billing-grade quota, so the current release accepts it rather than centralising the buckets in MySQL or Redis. A shared limiter is a possible follow-up.

### Audit-event durability under crash

The audit log dual-emits: every event is written to MySQL AND to slog (the secondary durable sink). Writes, denials, and auth events take the synchronous path and are durable before the request returns. Only sampled read-audit events ride an in-memory async queue (~8192 deep) so the read hot path does not wait on an INSERT.

On a graceful shutdown that queue is drained (bounded by a 30s deadline). On a hard kill (SIGKILL, OOM) the in-flight queue is lost, but those same events were already emitted to slog, so they survive in your OTel/log backend. The append-only MySQL audit table can therefore miss sampled read rows after a hard crash; the slog stream is the recovery source. The current release accepts this rather than shipping a write-ahead audit outbox (a possible follow-up). Alert on the `audit dropped` / `audit async record failed` WARN logs (see [Auth + authz dashboard](#auth--authz-dashboard)) to catch sustained drops.

## Upgrade agents

Agents upgrade by pushing a newer `.pkg` through your MDM. See your MDM's section in [mdm-deployment.md](mdm-deployment.md); for Fleet, see [fleet-deployment.md](fleet-deployment.md).

Never hand-install a newer pkg on a single MDM-managed Mac to "test the upgrade path". The MDM will re-deploy the old version on the next sync and you'll waste time debugging a drift you caused.

Validate a handful of Macs before rolling fleet-wide:

1. Scope the new pkg to a small canary team (5-10 Macs).
2. Wait 24h. Check the EDR admin UI: all canary hosts back online, `last_seen` fresh, no alert spike.
3. Re-scope to the full fleet.

## Rotate secrets

### Enroll secret

The enroll secret is shared between the server and the install script your MDM runs. Rotate it when you suspect it's leaked (committed to a public repo, shared over an insecure channel). Existing agents are unaffected: they authenticate with their per-host token.

```sh
cd /srv/fleet-edr
NEW_ENROLL_SECRET=$(openssl rand -hex 32)
printf '%s' "$NEW_ENROLL_SECRET" > secrets/enroll_secret
docker compose -f docker-compose.prod.yml --env-file .env restart server
```

Then update your MDM's secret variable (see your vendor's section in [mdm-deployment.md](mdm-deployment.md)) so freshly-enrolled Macs pick up the new value.

Important: `docker compose kill -s HUP server` does NOT rotate the enroll secret. SIGHUP is TLS-only. Use `restart`.

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

Active TLS connections stay up. New handshakes pick up the new cert on the next `ClientHello`. Verify with:

```sh
openssl s_client -connect <server>:443 -servername <server> </dev/null 2>/dev/null \
    | openssl x509 -noout -dates
```

Wire this into your Let's Encrypt renewal hook so it happens automatically on renewal.

### MySQL root password

Less common (MySQL isn't exposed outside the Compose network), but:

```sh
cd /srv/fleet-edr
NEW_MYSQL_PASS=$(openssl rand -hex 24)
printf '%s' "$NEW_MYSQL_PASS" > secrets/mysql_root
printf 'root:%s@tcp(mysql:3306)/edr?parseTime=true&tls=false' "$NEW_MYSQL_PASS" > secrets/edr_dsn
docker compose -f docker-compose.prod.yml --env-file .env up -d --force-recreate mysql server
```

The named volume persists across recreate; no data loss. The server restarts once mysql is ready (Compose healthcheck gates it).

### EDR root secret

`EDR_SECRET_KEY` is the deployment root secret. Every long-lived server-side key is derived from it via HKDF-SHA256 under a versioned label (key separation; see `internal/keyring`), so a deployment provisions one secret rather than one per purpose. The derived keys are:

- The host-token HMAC pepper that hashes + verifies every agent bearer token.
- The cookie signing key that signs every OIDC state cookie (state, nonce, PKCE verifier on the round-trip to the IdP), the WebAuthn registration session cookie used during break-glass redemption and second-key enrollment, and server-minted session metadata cookies.

It is required on every boot, OIDC or not, because the host-token pepper is always needed. Rotate it yearly, or immediately on any suspicion of host compromise (stolen disk image, leaked secret file, retired operator who had filesystem-level access). The key must be at least 32 bytes; the config layer rejects shorter values at boot with a focused error.

In production deliver it via the docker-secret-style `EDR_SECRET_KEY_FILE` mount (same pattern as `EDR_DSN_FILE` and `EDR_ENROLL_SECRET_FILE`). Never paste plaintext into a compose env block. `docker inspect` reads env, but not bind-mounted secret files.

```sh
cd /srv/fleet-edr
NEW_SECRET_KEY=$(openssl rand -hex 32)
printf '%s' "$NEW_SECRET_KEY" > secrets/secret_key
chmod 0600 secrets/secret_key
docker compose -f docker-compose.prod.yml --env-file .env restart server
```

What the restart invalidates:

- **Every host token.** The derived pepper changes, so every enrolled agent's stored hash stops matching. Agents 401 on their next request and re-enroll automatically via the deployment secret (the re-enrollment-on-revocation path). This is a fleet-wide re-enroll: expect a burst of enroll traffic. Plan the rotation accordingly.
- **Every active session.** All signed-in operators land back on `/ui/login` and must re-authenticate via OIDC (or the break-glass surface). Coordinate the restart with on-call so nobody is mid-triage.
- **In-flight OIDC sign-in flows.** Anyone partway through the IdP round-trip will hit the callback with a state cookie the new key can't verify; their browser surfaces an OIDC error and they have to restart from `/ui/login`. The window is typically seconds, but a slow IdP / MFA prompt can stretch it to minutes.
- **In-flight break-glass WebAuthn registration sessions.** Any operator who has loaded a bootstrap-token redemption page but not yet completed the authenticator ceremony will fail at the final step. Reload the redemption URL to restart the ceremony; the bootstrap token itself is not consumed until the credential write succeeds. See [breakglass.md](breakglass.md#first-boot-redemption) for the redemption flow.

Unrelated persisted records (password hashes, registered WebAuthn credentials, audit rows) are NOT touched: rotation neither deletes nor modifies them. The host-token hashes in the `enrollments` table are persisted too, but rotating the root secret makes them stop matching, which is exactly what forces the fleet-wide re-enroll noted above. So the only durable state a rotation effectively invalidates is the host-token hashes; everything else is either ephemeral signed state or left intact.

## Backup and restore

The entire EDR state is in the MySQL `edr` schema. The named volume `edr-mysql-data` is the source of truth; nothing else is stateful.

### Logical backup

```sh
docker compose -f docker-compose.prod.yml exec -T mysql \
    mysqldump --single-transaction --routines --triggers \
    -uroot -p"$(cat secrets/mysql_root)" edr \
    | gzip > "edr-$(date +%Y%m%d).sql.gz"
```

`--single-transaction` works because every EDR table is InnoDB, so the backup doesn't block writes.

Ship the `.sql.gz` off-host (S3, Backblaze B2, borg, whatever your standard is). Keep at least 30 days, longer if your compliance regime says so.

### Restore

Spin up a fresh server stack with empty volumes, then:

```sh
gunzip -c edr-YYYYMMDD.sql.gz \
    | docker compose -f docker-compose.prod.yml exec -T mysql \
      mysql -uroot -p"$(cat secrets/mysql_root)" edr
```

The agents' persisted host tokens keep working after a restore: the `hosts` table survives, so enrollments don't churn. Expect the `last_seen` gauge to tick back to current within ~30s as agents reconnect.

Test your restore path quarterly. An untested backup is a hope, not a backup.

### Volume snapshots

If your host filesystem is ZFS / Btrfs / LVM-thin, volume snapshots are faster than logical backups. Point-in-time recovery via binlog replay is not supported because the server doesn't emit binlogs by default; rely on logical backups + snapshots for now.

## Retention tuning

The server deletes events older than `EDR_RETENTION_DAYS` (default 30) on a fixed hourly schedule. The knob lives in the server's environment; restart to take effect.

Three common scenarios:

1. **Compliance requires 90 days of event history.** Set `EDR_RETENTION_DAYS=90`. Monitor `edr.retention.rows_deleted` and the DB disk usage for a week to confirm storage is sized right.
2. **Disk is filling up, want to shrink window.** Set a smaller `EDR_RETENTION_DAYS` value. The next retention run will delete events older than the new cutoff. Expect one large deletion, then normal churn.
3. **Want to keep events forever for a forensic investigation.** Set `EDR_RETENTION_DAYS=0`. Retention is disabled. Re-enable once the investigation is complete to avoid unbounded growth.

Alerts are NOT deleted by retention. They stay until you delete them via the admin UI. A resolved alert pointing at an event that retention has purged will still render, with the event references 404ing.

### Curbing event volume at the source

Retention bounds how long events live; two levers reduce how many are written in the first place (issue #408):

- **`snapshot_heartbeat` events are no longer persisted.** The server applies their freshness side effect (the `processes.last_seen_ns` bump that exempts a live snapshot row from the 6h TTL force-exit) at ingest and drops them, so they never occupy an `events` row. Watch `edr.ingest.heartbeats_dropped` to see the row-count savings.
- **`EDR_PROCESS_RECONCILE_INTERVAL` is the heartbeat-rate lever** (agent-side, default `60s`). Each interval the agent emits one heartbeat per live snapshot PID (~900 on a normal macOS host). Heartbeats no longer cost an `events` row, but they still cost an ingest request and a freshness UPDATE; raising the interval (for example `EDR_PROCESS_RECONCILE_INTERVAL=5m` in `/etc/fleet-edr.conf`) cuts that traffic ~5x. Keep it well under the 6h stale-process TTL so a live snapshot row is always re-freshened before the TTL would force-exit it.
- **Repetitive network/DNS telemetry is coalesced automatically** (agent-side, fixed `10s` window). Within each window the agent collapses repeated identical connection 5-tuples and repeated DNS lookups into one representative event plus a `coalesced_count`, preserving the earliest timestamp and (for DNS) the union of resolved addresses. The window is a fixed constant, deliberately well under the 30s DNS-to-connect beacon-correlation window so coalescing can never push a representative outside it.

## Process-tree freshness (issue #6)

ESF is best-effort and exit events go missing under kernel back-pressure, sysext crashes, and agent restarts. Two reconcilers cooperate to keep the process tree from filling with forever-green ghost rows.

**Server-side TTL** (fixed `6h`). On each pass the server force-greys any process whose `fork_time_ns` is older than the TTL and which still has no `exit_time_ns`. The synthesized exit is tagged `exit_reason = ttl_reconciliation`. The reconciler pass runs every `10m`.

**Agent-side `kill(pid, 0)` sweep** (`EDR_PROCESS_RECONCILE_INTERVAL`, default `60s` on the agent). Every interval the agent walks its in-memory PID table and probes each tracked PID with `kill(pid, 0)`. Any PID that returns `ESRCH` ("no such process") is gone: the agent emits a synthetic exit event tagged `exit_reason = host_reconciled`, which the server records on the row. PIDs younger than 30s are skipped to avoid racing the exec; at most 256 synthetic exits are emitted per pass to bound queue pressure on a host that just lost a large burst of exits. Set the interval to `0` on the agent (via `/etc/fleet-edr.conf` or env) to disable; useful only for narrow QA where synthetic exits would distort what a clean ESF feed looks like.

The two reconcilers are complementary: the agent closes rows within ~minute granularity for hosts that are alive and reachable, and the server's TTL is the safety net for hosts that go offline before they can reconcile themselves.

**Long-lived processes captured at extension startup.** The extension enumerates the live process table when it starts so processes that pre-dated subscription (Safari, Slack, system daemons, login session processes) appear in the tree alongside organic fork/exec activity. These rows would otherwise be force-greyed by the 6h TTL because nothing further happens to them at the kernel level: they just keep running. To prevent that, the agent emits a periodic liveness heartbeat for each such process on the same `EDR_PROCESS_RECONCILE_INTERVAL` cadence as the kill-zero sweep; the server uses those heartbeats to extend the per-row freshness window. No additional configuration knob is exposed for the heartbeat; disabling `EDR_PROCESS_RECONCILE_INTERVAL` disables both behaviours together.

## Metrics and monitoring

Server exports OpenTelemetry metrics via OTLP/gRPC to the endpoint in `OTEL_EXPORTER_OTLP_ENDPOINT`. No Prometheus scrape endpoint is provided. See [install-server.md](install-server.md#otel-metrics-and-logs).

Core metrics to chart:

| Metric | Type | What to watch |
| --- | --- | --- |
| `edr.events.ingested` | counter | Spikes up = agent fleet healthy. Drop to zero = ingress wedged |
| `edr.alerts.created` | counter | By `rule_id` + `severity`. Sudden spike warrants a look |
| `edr.enrolled.hosts` | gauge | Should match your MDM's scoped Mac count |
| `edr.offline.hosts` | gauge | Hosts whose `last_seen` is older than 5 min. Keep near zero |
| `edr.retention.rows_deleted` | counter | Should tick up every retention run (hourly) |
| `edr.processes.ttl_reconciled` | counter | TTL-driven synthetic-exit emissions. The counter only increments when the reconciler synthesises an exit (it no-ops when there's nothing stale), so a non-zero rate or spike means the reconciler is firing, typically because a host missed an exec/exit pair. A sustained zero is ambiguous (either no stale processes to reconcile, or the reconciler has wedged); rely on logs/traces or a separate heartbeat to distinguish |
| `db.sql.latency` | histogram | DB call latency, emitted by the otelsql driver instrumentation (not a bespoke metric). p99 creeping up = DB overloaded or a slow query regressed |
| `edr.agent.queue.dropped` | counter | Non-zero = agent's local SQLite queue hit its cap. Investigate connectivity |

Recommended alerts (SigNoz, Grafana, wherever your OTel backend lives):

- `edr.offline.hosts > 10% of edr.enrolled.hosts for 15m` - fleet-wide connectivity issue.
- `rate(edr.events.ingested[5m]) == 0 for 5m` - server isn't receiving events. Either all agents are offline (see above), ingress is broken, or the server wedged.
- `rate(edr.retention.rows_deleted[1h]) == 0 for 2h` when `EDR_RETENTION_DAYS > 0` - retention job stuck.
- `rate(edr.agent.queue.dropped[5m]) > 0` - endpoints losing data.

Server logs go through the same OTLP pipeline (via `otelslog`) with `service.name=fleet-edr-server`. Use them for audit-style queries like "who resolved alert X" (look for `edr.admin.action=alert_update` log events with `user.id`).

### HTTP server (RED) dashboard

A starter SigNoz dashboard for the inbound HTTP surface lives at `config/observability/edr-http-server-dashboard.json`. It covers six panels (Rate / Errors / Duration): request rate by route, 5xx error rate by route, p95 and p99 latency by route, request rate by status code, and request rate by method. Import via the SigNoz UI: **Dashboards -> New Dashboard -> Import JSON** -> paste the file contents -> save. Because the access-log middleware no longer logs healthy 2xx/3xx at INFO, this dashboard (not log grep) is the volume + latency signal. All panels read the OTel `http.server.request.duration` histogram, which SigNoz stores under Prometheus-style suffixes: rate/volume panels query `http.server.request.duration.count`, latency quantiles query `http.server.request.duration.bucket`.

### Auth + authz dashboard

A starter SigNoz dashboard for the auth + authz surface lives at `config/observability/edr-authz-dashboard.json`. It covers four panels: audit events by decision, denied + errored events by action, auth rejections by reason, and an audit-activity table by action. Import via the SigNoz UI: **Dashboards -> New Dashboard -> Import JSON** -> paste the file contents -> save.

Every audit emission sets three attributes on the active request span (`server/identity/internal/audit`): `edr.audit.action` (e.g. `auth.login.success`, `authz.host_read`, `enrollment.revoke`), `edr.audit.decision` (`allow` | `deny` | `error` | `unspecified`), and `edr.audit.reason` (a machine-readable code, empty for context-free rows). These live on the **traces** signal, so every panel queries traces rather than logs. Bearer/session rejections additionally set `edr.auth.reason` (`invalid_token`, `missing_bearer`, ...) on the span, which the auth-rejections panel groups on. The same events dual-emit to slog (allow at INFO, deny/error/break-glass at WARN) for log-side queries, but the dashboard binds to the span attributes so it pivots on the same dimensions the trace UI uses.

Recommended alerts to add against this dashboard:

- `rate(edr.audit.write_failures[5m]) > 0`: paging condition. This counter increments once per audit row the slog dual-emit captured but the DB rejected; the audit log's append-only invariant is broken if it is ever non-zero.
- `rate(edr.audit.action="auth.breakglass.failure") > 5/min for 5m`: brute-force on the recovery surface. Cross-check `EDR_BREAKGLASS_IP_ALLOWLIST`.
- `rate(edr.audit.decision="error" AND edr.audit.reason matches state_mismatch|exchange_failed) > 0 for 5m`: IdP misconfig or load-balancer affinity issue (see [`okta-setup.md`](okta-setup.md) troubleshooting table).

## Handling offline hosts

A host is "offline" when the server hasn't heard from it in >5 min. The admin UI tags these rows with a red dot.

Common causes, in order:

1. **Endpoint is powered off / asleep.** Nothing to do; the host reconnects on next wake.
2. **Network-level change.** Moved to a VPN / Wi-Fi with egress filtering. Validate `curl -v https://<edr-server>/livez` from the endpoint.
3. **Agent crashed.** `sudo launchctl print system/com.fleetdm.edr.agent` shows `state = running`? If not: `sudo launchctl kickstart -k system/com.fleetdm.edr.agent`.
4. **Enrollment revoked.** Check `POST /api/enrollments/{host_id}/revoke` logs. Re-enroll by re-running the MDM install-script and restarting the daemon.
5. **DB clock skew / server down.** `edr.enrolled.hosts` gauge returning -1 means the DB query failed.

If a host has been offline for >30 days and you expect it to be permanently gone (retired laptop), revoke the enrollment from the UI (`Hosts > <host> > Revoke enrollment`) so its host-token can no longer be used.

## Application control

Application Control replaces the singleton blocklist with operator-managed policies (named, versioned, audited) containing typed rules. The AUTH_EXEC handler in the system extension consults the active snapshot on every exec and denies the first matching rule with `action=BLOCK` and `enforcement=PROTECT`. Precedence is CDHASH → BINARY → SIGNINGID → TEAMID. CERTIFICATE and PATH rules are accepted by the REST surface but deferred to Phase B (leaf-cert cache / Launch Services indirection).

Two unconditional carve-outs run before any rule:

1. **Platform-binary carve-out.** If the kernel sets `target.is_platform_binary` (launchd, xpcproxy, fseventsd, kextd, sysextd, WindowServer, etc.) the handler returns ALLOW with the kernel cache pinned. An admin who pastes the SHA-256 of `/sbin/launchd` into a BINARY rule will NOT brick the host: the carve-out fires before the snapshot walk.
2. **Self-allow failsafe.** The agent / extensions / host app (matched by both Fleet's team_id and the exhaustive Fleet bundle-id allowlist) ALLOW unconditionally. A misconfigured rule cannot block the EDR itself.

### BINARY rules and the deadline-fallback posture

A BINARY rule matches the file's SHA-256. The hash is computed synchronously on the AUTH_EXEC callback thread, with the budget bounded by the kernel-supplied `es_message_t.deadline` minus a 500 ms safety margin for the post-hash work. The agent closes the pre-RC bypass primitive where the first exec of any binary slipped past BINARY rules while the cache filled asynchronously (#208).

If the hash cannot finish in time (large binary, slow disk, or the file is unreadable due to a TOCTOU replace between AUTH and read), the snapshot's `deadline_fallback` field drives the verdict:

| Posture | Verdict on deadline / read failure | Event emitted | When to pick |
| --- | --- | --- | --- |
| `fail-closed` (default) | DENY | `application_control_undecided` with `verdict=deny` | High-assurance pilots. A binary the EDR cannot identify in time does not run. |
| `fail-open` | ALLOW | none | Demo-equivalent posture. The cold-cache window stays open; pick this only if "no unexpected blocks" outweighs "no first-exec bypass." |
| `audit-only` | ALLOW | `application_control_undecided` with `verdict=allow` | Tuning a fleet before flipping to `fail-closed`. Count how often the fallback fires without changing exec behaviour. |

On `deadline-exceeded` or `read-failed` outcomes the SHA-256 cache is NOT populated, so subsequent execs of the same binary retry the hash computation. Repeated `application_control_undecided` events for the same `path` therefore indicate either a binary that consistently blows the 500 ms safety margin (size + disk-read combination) or a TOCTOU race the agent is hitting deterministically; the path + `file_size_bytes` fields are the disambiguator.

The agent wires the posture through the snapshot payload but does NOT yet persist a per-policy value in the database; every snapshot ships with `fail-closed`. A planned follow-up adds a DB column and the REST surface to set it per policy.

### Legacy endpoints

The `add-application-control` OpenSpec change deleted the singleton `/api/policy` endpoints and the `set_blocklist` agent command. The new REST surface lives under `/api/v1/app-control/*`.

The `EDR_LAUNCHAGENT_ALLOWLIST` env var is different: it tells the server's `persistence_launchagent` detection rule which LaunchAgent paths are benign and should not trigger alerts. Set it as a comma-separated list of absolute paths.

`EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST` is the parallel knob for the `privilege_launchd_plist_write` rule. Apple-signed platform binaries (installd, system_installd, ...) are always allowed; this list is for non-Apple agents that legitimately drop daemons under `/Library/LaunchDaemons/` (Munki, Kandji, JumpCloud, etc.). Set it as a comma-separated list of code-signing team IDs, e.g. `T4SK8ZXCXG,XYZW0KL1Q9`.

`EDR_SUDOERS_WRITER_ALLOWLIST` is the parallel knob for the `sudoers_tamper` rule. Direct writes to `/etc/sudoers`, `/etc/sudoers.d/*`, `/private/etc/sudoers`, or `/private/etc/sudoers.d/*` always fire unless the writing process's path is on this list. The two path forms are the same file (`/etc` is a symlink to `/private/etc` on macOS and ES reports whichever path the caller opened), so alerts can surface either, but the allowlist still applies in both cases. visudo / sudoedit don't need to be allowlisted: they write a temp file and atomically rename it, so the rule never sees their open events. The typical use case is allowlisting an MDM agent's binary path. Set it as a comma-separated list of absolute paths, e.g. `/usr/local/bin/munki-managed-installer`.

`EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` tunes the `suspicious_exec` rule. The rule has two trigger shapes within a 30-second window of the shell's exec: `non-shell → shell → /tmp/binary` (the dropper form), and `non-shell → shell` followed by an outbound network connection from that shell or a descendant (the curl-pipe-sh form). Both shapes capture commodity-attack patterns AND match interactive admin SSH sessions running scripts from `/tmp/` or curling tools (the chain `/usr/libexec/sshd-session → /bin/zsh → /bin/bash /tmp/script.sh` is identical at the syscall level to an attacker pivoting in via a compromised SSH key). The allowlist suppresses the rule when the **non-shell ancestor's path** is on the list, for both trigger shapes. The shell and the temp-binary or outbound connection still need to be there in their normal positions; this knob only changes which root processes count as benign.

For developer fleets and admin-managed hosts where interactive SSH is normal, the recommended value is

```sh
EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST=/usr/libexec/sshd-session,/Applications/Terminal.app/Contents/MacOS/Terminal,/Applications/iTerm.app/Contents/MacOS/iTerm2
```

Add the absolute path of any other terminal emulator your fleet uses (Hyper, kitty, Alacritty, Warp, ...). Tmux and screen don't need to be on the list: they appear as the SHELL in the chain (non-shell → tmux → /tmp/...), and tmux's parent is always one of the entry points already covered.

For servers that **shouldn't** see interactive SSH (production databases, build runners with key-based access only), leave this empty. The unsuppressed `suspicious_exec` chain is then a high-confidence attacker indicator.

The trade-off is real: an attacker who pivots into a host via a compromised SSH credential follows the same chain as a legitimate admin, so allowlisting `sshd-session` reduces noise but also blinds the rule to that one attacker path. Other rules (network beaconing, persistence drops, credential access) catch the same actor through different signal, but the residual coverage gap is worth knowing about.

`EDR_DISABLED_RULES` is the **whole-rule** disable knob. When an allowlist isn't expressive enough to silence a noisy rule for a given environment, set the comma-separated list of `rule_id` values (the IDs printed by `GET /api/rules`) to drop them from the engine at boot. Example: a fleet whose admin workflow runs AppleScript that curls from a vendor URL might disable `osascript_network_exec` outright until a follow-up tunes the rule:

```sh
EDR_DISABLED_RULES=osascript_network_exec
```

The rule is then gone from the engine's active set AND from `GET /api/rules`, so dashboards, alerts, and `tools/gen-rule-docs` all stop referencing it. The disable is **boot-time only**: apply a new value by restarting the server; hot reload is intentionally out of scope per the spec contract. Unknown rule IDs in the list log a WARN at boot (`EDR_DISABLED_RULES references unknown rule_id...`) but don't fail the boot, so a stale config doesn't take a deployment down.

Prefer the allowlist knobs above when they're expressive enough: they silence the noise without giving up the rule's coverage for genuinely-malicious inputs. Reach for `EDR_DISABLED_RULES` only when the rule is wrong for the environment and an allowlist would let through too much.

## Common troubleshooting

**Readyz says `db: error`.** MySQL unreachable. Check `docker compose ps` and `docker compose logs mysql`. Restart the stack if MySQL is stuck in a restart loop.

**Server log: `exporter export timeout`.** OTel collector unreachable. Fix connectivity to `OTEL_EXPORTER_OTLP_ENDPOINT` or unset the var to disable metrics export. Server functionality is unaffected; only telemetry is dropped.

**Admin UI shows a host but `last_seen` is stuck >30 min ago.** Either the host is offline (see above) or its agent is running but failing to post events. SSH to the host, tail `/var/log/fleet-edr-agent.log`; expect TLS / network / 401 errors if the agent is failing to reach the server.

**Alerts appear for a binary you know is benign.** Add its path to `EDR_LAUNCHAGENT_ALLOWLIST` (if it's a LaunchAgent), or add an allow rule in the UI for the rule that fired. Mark the existing alerts as `resolved` once you've confirmed they're false positives.

**All agents went offline at once.** Check the EDR server first (`/readyz`), then your ingress / LB, then your TLS cert's expiry. If the cert expired, see "Rotate secrets > TLS cert" above; agents will reconnect once the cert is fixed without needing a restart on their end.

**MySQL disk is full.** Shrink `EDR_RETENTION_DAYS`, restart the server, wait for one retention run. If that isn't enough, the events table is larger than your disk; you need either more disk or a shorter window. There is no online rebalance: expand storage and restart.

**`docker compose up -d` fails with `volume edr-mysql-data is in use`.** A previous server process didn't shut down cleanly. `docker compose down && docker compose up -d` usually clears it. Do NOT `docker volume rm edr-mysql-data`; that wipes the database.
