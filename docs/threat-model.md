# Threat model

This document is Fleet EDR's threat model. It exists for three audiences:

1. **Engineers reviewing security-sensitive PRs**: "does this widen one of the listed threats? does it close a gap?"
2. **Pilot-customer security reviewers** asking what attack surface the vendor considered before installing the agent on managed endpoints.
3. **Future contributors** evaluating where investment is most needed.

Format is STRIDE per component, with each cell either citing the existing mitigation or flagging a `GAP` with severity (high / medium / low) reflecting pilot-deployment impact, not theoretical worst-case.

Scope is the system as it ships on the current v0.3.0 pre-release line: Go agent + Swift system extension + Swift network extension on macOS endpoints; a Go server that can run as one combined `fleet-edr-server` binary or split into a standalone `fleet-edr-ingest` tier; a MySQL control plane plus a ClickHouse event archive (ADR-0015, the raw `events` table has left MySQL); an embedded React UI; a persistent agent control channel (a bidirectional gRPC stream multiplexed onto the same HTTPS listener, ADR-0016 and issue #477); operator and non-human service-account API auth (ADR-0013) resolving to one unified principal model (ADR-0017); and MDM-driven deployment. Out of scope is everything in the closing section.

## Trust boundaries

```text
+--------------------------------------------------------------------------+
|                       Endpoint (macOS, root)                             |
|  +---------------------+  +-----------------+  +-------------------+    |
|  |  System Extension   |  |  Network Ext.   |  |     Agent (Go)    |    |
|  |  (Swift, ESF)       |  |  (Swift, NEFD)  |  |  (XPC client)     |    |
|  +----------+----------+  +--------+--------+  +---------+---------+    |
|             |                      |                     |              |
|             +-----------XPC--------+---------------------+              |
|                                    |                                    |
+------------------------------------|------------------------------------+
                                     |
            HTTPS (TLS 1.3), one listener/port, Bearer host_token
        POST /api/events (upload)  +  gRPC control stream (push commands)
                                     |
+------------------------------------v------------------------------------+
|                        Server (Go, distroless container)                 |
|  +---------+  +-----------+  +-----------+  +-----------+  +---------+   |
|  | Ingest  |  | Detection |  | Control   |  | Admin/API |  |UI(embed)|   |
|  | API     |  | Engine    |  | gateway   |  | session + |  | React   |   |
|  | (host   |  | (queue    |  | (gRPC,    |  | SA bearer |  |         |   |
|  |  token) |  |  claim)   |  |host token)|  | token)    |  |         |   |
|  +----+----+  +-----+-----+  +-----+-----+  +-----+-----+  +----+----+   |
|       |             |              |              |             |        |
+-------|-------------|--------------|--------------|-------------|--------+
        |             |              |              |             |
   +----+----+   +----+-----------+  +--------------+----+   Browser session
   |ClickHouse|  | MySQL (private):|  |  OTLP (gRPC)      |   / SA bearer token
   | archive  |  | control plane,  |  |        |         |
   |(private) |  | process graph,  |  | OTel collector   |
   | events   |  | event_queue,    |  +------------------+
   +----------+  | alerts+evidence,|
                 | sessions, princ.|
                 +-----------------+
```

Trust assumptions:

- **The MDM is a trust anchor.** It delivers the signed `.pkg` and the two configuration profiles (system-extension allowlist, network-extension allowlist). A compromised MDM is out of scope.
- **The endpoint kernel and Apple frameworks are trusted.** ESF, NEFD, launchd, SIP. Their integrity is Apple's responsibility.
- **The MySQL instance is on a private network.** MySQL now holds the control plane, the derived process graph, the ephemeral `event_queue` work queue (ADR-0016), alerts and their self-contained evidence copies, sessions, and principals; the raw event firehose has moved out (ADR-0015). Direct DB-network compromise is out of scope; anything past the Compose network is the operator's responsibility.
- **The ClickHouse event archive is on a private network.** The raw event firehose (`events`) lives only in ClickHouse (ADR-0015), reached over a `clickhouse-go` DSN that is never exposed outside the private/Compose network. Direct ClickHouse-network compromise is out of scope on the same terms as MySQL; securing the port, the DSN credential, and at-rest encryption is the operator's responsibility. Alert evidence is copied into MySQL at alert-creation time (`alert_event_payloads`), so a finding survives independently of the archive's native TTL.
- **Telemetry leaves the server boundary when OTLP export is configured.** With `OTEL_EXPORTER_OTLP_ENDPOINT` set, traces, logs (including the dual-emitted audit records), and metrics are exported to an external OTel collector. Securing that collector (transport, authn, retention) is the operator's responsibility. The audit dual-emit deliberately depends on this egress so an in-server tamper that drops MySQL writes cannot erase the off-box record.

## Per-component threats

### 1. Agent daemon (Go, runs as root via LaunchDaemon)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Unprivileged process impersonates the agent over XPC to the sysext. | The sysext registers its Mach service via `NSEndpointSecurityMachServiceName` in `extension/edr/extension/Info.plist` (system-extension-side, not a LaunchDaemon `MachServices` entry). Every accepted peer is constrained by `xpc_connection_set_peer_code_signing_requirement` (see `extension/edr/shared/XPCEventServer.swift`) with the agent's expected team-ID code-signing requirement; connections that don't satisfy the requirement are dropped before any message is processed. |
| Tampering | Local attacker overwrites the agent binary or LaunchDaemon plist. | SIP protects the install path; the agent binary is Developer-ID-signed and notarized; modification breaks the signature and macOS refuses to launch. |
| Repudiation | Command lifecycle goes unlogged. | Every command transitions (`pending` → `running` → `success`/`failure`) are persisted both locally (slog) and server-side (`commands` table). Admin actions emit a WARN-level audit log line. |
| Information disclosure | Sensitive payload data leaks to the agent log. | `os.log` argv redaction; agent's slog handler does not print full event payloads at INFO level; sensitive fields stay at DEBUG (off by default). |
| Denial of service | SQLite queue grows unbounded, breaks the agent. | A fixed 500 MiB queue cap is enforced; over-cap rows are dropped + counted in `edr.agent.queue.dropped` (with the `lossy` attribute distinguishing data loss from already-delivered trims). Documented in [`operations.md`](operations.md). |
| Elevation of privilege | A network attacker uses the root-running agent to execute arbitrary code. | Agent only executes typed commands (`kill_process`, `set_application_control`) delivered by the server over either transport (the `GET /api/commands` short-poll or the persistent gRPC control stream, component 8), both authenticated by the same per-host bearer token and both feeding one shared executor and a durable cross-transport dedup ledger (`agent/commandledger`, issue #558) so a pushed command cannot be replayed by the poll path. The command-type → handler mapping is exhaustive (`agent/commander/commander.go`); unknown types are rejected. A queued command is also bounded in time: `kill_process` addresses a pid, pids are reused, and a command delivered long after it was issued could terminate an unrelated process, so the server ages a command out of the delivery window rather than handing it to an agent late, and the agent refuses a kill whose target generation no longer matches (issue #627). `set_application_control` carries an operator-authored Application Control blocklist the agent applies but cannot itself originate: it is gated by the RBAC chokepoint, versioned, and audited server-side (see the Detection-content row below). |

### 2. System extension (Swift, ESF)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Another process registers as the ESF client. | macOS only loads system extensions signed with the developer's team ID; the `com.apple.developer.endpoint-security.client` entitlement is granted by Apple by application; the sysext's bundle ID is unique. |
| Tampering | Attacker swaps the sysext bundle on disk. | SIP-protected, signed + notarized, MDM-pinned via `.mobileconfig`; replacement requires the same team ID. |
| Repudiation | Sysext drops events without trace. | ESF muting is per-event-type and logged via `os_log`; metrics flow through the agent. |
| Information disclosure | Paths or argv leak via `os_log`. | `%{public}s` only on non-sensitive fields; `%{private}s` (default) for paths and argv; production builds redact private fields to `<private>`. |
| Denial of service | Event flood overwhelms the sysext, dropping events. | ESF queues per-client; the sysext mutes when it falls behind (Apple-defined behaviour), with the muted event type logged so operators can detect it. |
| Elevation of privilege | Bug in event handling becomes root code execution. | Sysext code surface is small (event subscription, JSON serialization, XPC send); ESF's interface is Apple-vetted; XPC is typed (no arbitrary deserialization). |

### 3. Network extension (Swift, NEFilterDataProvider)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Attacker installs a competing NE filter. | `NEFilterDataProvider` profiles are MDM-installed and persist until the MDM revokes them; multiple filters can coexist but each has its own bundle ID + team ID fingerprint. |
| Tampering | NE binary swapped. | Same as sysext (SIP, signed, notarized). |
| Repudiation | Connection event dropped silently. | Per-connection ID; dropped flow logs via `os_log`. **GAP, low**: no dedicated `edr.network.events.dropped` counter. |
| Information disclosure | NE captures connection payload bytes. | Configured for **flow-handling-only**: 5-tuple + PID + signing context. Payload bytes are deliberately not captured. This sidesteps wiretap-law concerns and reduces the data-at-rest footprint. |
| Denial of service | NE's allow-or-deny verdict latency stalls all connections. | Verdicts are inline with a small per-decision budget; framework falls back to `verdictAllow` if the client extension is unresponsive. |
| Elevation of privilege | NE bug → root. | NE runs as root by Apple design; minimal surface; uses Apple-vetted `NEFilterDataProvider` API. |

### 4. Server (Go, distroless container)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Attacker enrolls a fake host or impersonates an enrolled one. | Enrollment requires the shared `EDR_ENROLL_SECRET` plus a hardware UUID; subsequent requests carry a self-validating signed per-host bearer token (`v1.<claims>.<HMAC-SHA256>`, keyed off the deployment root secret `EDR_SECRET_KEY` via `internal/keyring`; `server/endpoint/internal/signedtoken`). The server verifies it statelessly on every request (HMAC signature + expiry + an in-memory revocation snapshot, no per-request DB lookup), so a DB-only leak can neither verify nor forge a token. Tokens are scoped: events with `host_id ≠ token's host_id` are rejected. |
| Tampering | Attacker modifies events or admin actions in flight. | TLS 1.3 unconditionally (`MinVersion: tls.VersionTLS13` in `server/httpserver/tls.go`): the only clients are our own modern Go agent and modern browsers, so there is no legacy TLS 1.2 opt-out to maintain. TLS 1.3 negotiates its own fixed cipher list, so there is no cipher-suite knob to restrict. The gated exception is `EDR_TLS_TERMINATED_BY_PROXY`, where TLS terminates at a front proxy and the server listens plaintext on its bind address (which must therefore never face agents or the internet directly). The same listener carries both the REST/upload surface and the gRPC control stream (component 8). |
| Repudiation | Admin action goes unaudited. | Every admin endpoint emits a WARN-level slog line plus span attributes (`edr.admin.action`, `edr.admin.actor`, `edr.admin.reason`). Logs flow via OTLP to an external sink, so an in-server tamper cannot retroactively erase the trace export. |
| Information disclosure | Database or backup leak exposes credentials. | Passwords Argon2id-hashed; host tokens are self-validating signed tokens (`v1.<claims>.<HMAC-SHA256>`) keyed off `EDR_SECRET_KEY`, and service-account credentials are SHA-256-hashed at rest (ADR-0013), so a DB-only leak can neither verify nor forge either; the MySQL DSN, the ClickHouse DSN, the enroll secret, and `EDR_SECRET_KEY` are all loaded via `_FILE` paths (Docker-secrets style) so they are never in env-listing output; TLS 1.3 over the wire; `subtle.ConstantTimeCompare` for CSRF token comparison. **GAP, medium**: encryption at rest for the raw event archive is a deployment requirement, not enforced in code (component 7). |
| Denial of service | Login or enroll endpoint flooded. | Per-IP rate limiting on the break-glass surface (per-IP and per-email caps return `429 Too Many Requests` with `Retry-After`); per-IP rate limiting on enroll (`EDR_ENROLL_RATE_PER_MIN` default 30). The OIDC login path is gated by the IdP's own brute-force defences. Event ingestion is per-token, gated by enrollment. **GAP, low**: no per-host rate limit beyond the per-route caps. |
| Elevation of privilege | Browser-based attacker uses an admin session. | HttpOnly + Secure + SameSite=Lax session cookies; per-session CSRF token on every unsafe method; HSTS with `includeSubDomains`, two-year max-age; session secret is sanitized to a 256-char base64url charset on read/write. Day-to-day login goes through OIDC, so MFA is delegated to the IdP (Okta, etc.) and is enforced upstream of the EDR. The break-glass surface at `/admin/break-glass` requires WebAuthn (no password-only fallback): see [`breakglass.md`](breakglass.md). Authorisation is enforced at the OPA-backed chokepoint (`api.HTTPGate`) with role tiers (`super_admin`, `admin`, `senior_analyst`, `analyst`, `auditor`); the chokepoint also requires a fresh re-auth (default 30m, `EDR_REAUTH_WINDOW`) for destructive actions (`host.isolate`, `host.kill_process`, `host.run_script`, `alert.resolve` when severity=critical). |

### 5. UI (React, embedded in server)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Phished credentials. | Day-to-day login is OIDC, so MFA is delegated to the IdP and enforced upstream of the EDR. Break-glass (`/admin/break-glass`) is WebAuthn-mandatory (no password-only fallback), phishing-resistant by design. See [`okta-setup.md`](okta-setup.md) and [`breakglass.md`](breakglass.md). |
| Tampering | Cross-site scripting. | React's default JSX escaping; no `dangerouslySetInnerHTML` in the codebase; ESLint's `no-unsanitized` plugin gates PRs; CodeQL TypeScript SAST is wired. **GAP, medium**: no Content-Security-Policy header. |
| Repudiation | UI action not auditable. | Every state-changing action goes through a server endpoint with audit logging; the UI is a thin client. The audit log enforces an append-only invariant (a build-time test scans production source for any UPDATE / DELETE against `audit_events` and fails the build if it finds one). Each successful row is dual-emitted to slog at INFO with a stable attribute shape (`action`, `target_type`, `target_id`, `actor_email`, `edr.user.id`, optional `trace_id`, optional `payload`); the async writer also emits structured slog WARNs when it cannot enqueue or persist a row (queue_full, drain_deadline_exceeded, INSERT failure). Both flow through OTLP to the configured collector, so an in-server compromise that drops MySQL writes still leaves the OTel-side record. |
| Information disclosure | Wrong analyst sees the wrong alert. | The OPA-backed chokepoint (`api.HTTPGate`) gates every privileged endpoint by the actor's role binding (`super_admin`, `admin`, `senior_analyst`, `analyst`, `auditor`); requests outside the binding return `403` with a typed deny reason. The product is a single-instance deployment (each customer runs their own server); per-team alert scoping is a follow-on for future host-group / host scoped bindings. |
| Denial of service | UI hammers the read API. | Read endpoints are session-cookie authenticated; clients are admin-controlled. **GAP, low**: no pagination contract on list endpoints. |
| Elevation of privilege | UI bug runs commands without authorisation. | Every privileged endpoint requires the session cookie (HttpOnly, JS-invisible) plus the CSRF header (JS-readable); CSRF tokens never live in cookies; React Router does not synthesize cross-origin requests. |

### 6. MySQL data plane

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Captured DSN reused. | DSN provided via Docker secret file (`EDR_DSN_FILE`); MySQL not exposed outside the Compose network. **GAP, medium**: server connects as MySQL root; should be a least-privilege user with grants only on the EDR schema. |
| Tampering | Direct DB writes that modify alerts or enrollments. | Only the server has the credentials; the server's writes are auditable. |
| Repudiation | Audit rows removed from `commands` / `enrollments`. | Server audit also emits to `slog` → OTLP → external sink, so a DB tamper does not erase the trace export. |
| Information disclosure | DB compromise exposes credentials / retained data. | Argon2id for passwords; self-validating signed host tokens keyed off `EDR_SECRET_KEY` and SHA-256-hashed service-account credentials, neither verifiable nor forgeable from a DB-only leak. MySQL no longer holds the raw event firehose (ADR-0015); it retains the process graph, alerts, and the per-alert evidence copies in `alert_event_payloads` (which do contain event payloads). **GAP, medium**: no application-level encryption at rest for those payload copies; relies on storage-layer encryption (InnoDB tablespace encryption, host filesystem encryption), a deployment-time choice. The same at-rest concern for the full firehose is now on ClickHouse (component 7). |
| Denial of service | Disk fills with retained rows. | The retention runner now prunes only MySQL process records (`EDR_RETENTION_DAYS`, default 30; `server/detection/internal/pipeline/retention.go`), skipping alert-referenced rows; per-batch DELETE with `LIMIT` keeps the InnoDB lock footprint bounded, with an `edr.retention.processes.rows_deleted` counter. Raw-event disk growth moved to ClickHouse native TTL (component 7); the ephemeral `event_queue` is pruned by a leader-gated sweep after ack (ADR-0016). |
| Elevation of privilege | SQL injection. | Parameterized queries throughout (no `fmt.Sprintf` into queries); golangci-lint `sqlclosecheck` and `noctx` rules; integration tests against a real MySQL 8.4 instance in CI. |

### 7. ClickHouse event archive (visibility context)

The raw event firehose lives only in ClickHouse (ADR-0015), owned by the `visibility` bounded context and reached over a `clickhouse-go` DSN by both the combined server and the standalone `fleet-edr-ingest` tier.

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | A captured ClickHouse DSN is reused to read or write the archive. | The DSN is loaded via `EDR_CLICKHOUSE_DSN_FILE` (Docker-secret style, never in env-listing output); ClickHouse is not exposed outside the private/Compose network, so a stolen DSN still needs network reach the operator controls. **GAP, medium**: as with MySQL, the tier connects as a broadly-privileged ClickHouse user; a least-privilege grant scoped to the `events` table is a deployment-hardening item. |
| Tampering | Direct writes alter or delete archived events. | Only the server and the `fleet-edr-ingest` tier hold the DSN. Archived events are immutable and idempotent by `event_id`: `ReplacingMergeTree(ingested_at_ns)` collapses a re-delivered event and reads use `FINAL`, so an at-least-once re-send cannot forge a divergent record. Alert evidence is copied into MySQL (`alert_event_payloads`) at alert-creation time, so tampering with or expiring the archive cannot erase the events behind a finding. |
| Repudiation | Archived events vanish without trace. | Retention is native ClickHouse TTL (30 days by default, `PARTITION BY toYYYYMM(ingested_date)`): an expected lifecycle, not a tamper. The evidence behind every alert is self-contained in MySQL and outlives the archive TTL; operator-action audit is a separate identity-context trail dual-emitted to OTLP. |
| Information disclosure | An archive leak exposes the raw firehose (paths, argv, connection 5-tuples, signing identity, hashes). | ClickHouse is private-network-only and DSN-gated. The network extension deliberately captures flow metadata only (no payload bytes, component 3), which bounds what lands here. **GAP, medium**: no application-level encryption at rest for the archive; it relies on storage-layer encryption (ClickHouse volume encryption, or an S3 cold-tier's server-side encryption), a deployment-time choice, the same posture the MySQL `events` table carried before the cutover. |
| Denial of service | An ingest spike or unbounded growth overruns the archive. | Each `POST /api/events` does one batched archive INSERT (the native batch protocol: one prepared INSERT per request-batch, not per event) plus one `event_queue` append, returning 200 only after both succeed, so the per-request write cost stays bounded; the MySQL `event_queue` then decouples ingest from detection (ADR-0016) so an ingest burst drains rather than stalls detection or loses data; native TTL (a 30-day age-based expiry in `server/visibility/migrations-clickhouse/00001_events.sql`) caps the retention window so the archive cannot accumulate indefinitely, though a sustained ingest spike within that window is bounded by storage sizing, not by the TTL; a hot-to-S3 tiered-storage policy is designed in but disabled by default at pilot scale (ADR-0015). Cold-partition read spikes on UI-synchronous correlation reads are a named watch item (ADR-0015), gated by the #203 load test. |
| Elevation of privilege | ClickHouse SQL injection. | Parameterized queries throughout the store (positional `?` binds via `database/sql` / `sqlx`, `server/visibility/internal/clickhouse/store.go`); the event-type-to-column mapping for search is a fixed allowlist (`api.ArtifactField`), not string interpolation of caller input. |

### 8. Agent control channel (gRPC gateway)

The persistent control channel (ADR-0016, issue #477) is a bidirectional gRPC stream that pushes commands to a connected host in real time and carries outcomes back, replacing the `GET /api/commands` short-poll as the primary transport while the poll is retained as the degraded floor. Its server side (`server/response/internal/gateway`) is multiplexed onto the same HTTPS listener and port as REST/UI: one native HTTP/2 server dispatches `application/grpc` requests to the gateway and everything else to the REST/UI handler, so there is no separate control address to configure or firewall.

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | An unauthenticated peer opens a control stream and receives another host's commands. | The stream authenticates once at connect: the agent presents its host bearer token in gRPC metadata (`authorization: Bearer <token>`) and the gateway's stream interceptor verifies it with the same stateless `VerifyToken` the HTTP path uses (local signature + expiry + in-memory revocation snapshot, no DB read), pinning the host id into the stream context. A missing or invalid token is rejected before any frame is processed (`Unauthenticated`); a ServerFrame is only ever pushed to the connection bound to its `host_id`. At most one connection per host is held (a reconnect evicts the prior one), so a command is never delivered twice across a stale and a fresh stream. |
| Tampering | Command or outcome frames are altered in flight. | The stream rides the same TLS 1.3 listener as REST (component 4); the agent dials it over the same pinned-TLS trust as the upload client (`controlDialTarget`). Outcomes flow through the unchanged `UpdateStatus` transition rules, so a replayed or out-of-order outcome is a benign invalid-transition, not state corruption. |
| Repudiation | A pushed command or its outcome goes unlogged. | The command lifecycle is unchanged and MySQL-backed: the gateway is a second transport in front of the same commands table, so every transition is persisted and auditable exactly as on the poll path. Connection presence bumps last-seen on connect and on a 30s liveness cadence, which also emits a payload-free heartbeat frame to the agent so it can distinguish a stream this replica still holds from one it has forgotten; the agent reconnects when frames stop arriving. The last-seen write is bounded and runs after the heartbeat, so a stalled database cannot silence heartbeats fleet-wide and turn a datastore incident into a reconnect storm. |
| Information disclosure | The stream leaks command contents to the wrong host. | Host-id pinning at the interceptor plus one-connection-per-host registration confine every ServerFrame to its owning host; there is no topic subscription or fan-out an attacker could join. |
| Denial of service | Connection exhaustion or a slow agent stalls the gateway. | The gateway is the one sanctioned stateful tier (ADR-0010 amendment): it holds live connections and per-connection bookkeeping only, persists nothing durable, and a gateway loss just forces agents to reconnect and fall back to the retained short-poll with no command loss (all command state stays in MySQL). Per-connection send buffers are bounded (a full buffer defers to the 1s cross-replica watch rather than blocking, and a heartbeat is dropped rather than queued when the buffer is full so it can never displace a command); a revoked or expired token tears the connection down within the 5s revocation re-check. **GAP, low**: no explicit per-replica cap on concurrent control connections beyond the host population and OS limits. |
| Elevation of privilege | A malicious agent escalates via the stream. | Only typed frames cross it: outcome frames up (mapped to the same status lifecycle) and command frames down; there is no arbitrary deserialization and no server-side action a connected agent can originate. Commands themselves originate operator-side through the RBAC chokepoint (component 4 and the Detection-content cross-cutting row). |

### 9. MDM and install path

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Attacker pushes a fake `.pkg` claiming to be the EDR. | Pkg is Developer-ID-signed and Apple-notarized; macOS verifies the signature at install; the `.mobileconfig` profile binds the team ID expected for the system extension. |
| Tampering | Malicious post-install scripts. | Pkg post-install scripts live in `packaging/pkg/` and are reviewable; build is via the signed CI release workflow; no `curl \| bash` at install time. |
| Repudiation | Install / uninstall not logged. | macOS records `/var/log/install.log`; agent enrollment logs the host's hardware UUID + first-seen time on the server side. |
| Information disclosure | Enroll secret leaks via process listing or shell history. | The pkg postinstall script (and Fleet's install-script contract, see `packaging/pkg/scripts/postinstall`) writes the enroll secret to root-owned `/etc/fleet-edr.conf`; the agent reads that file via the layering in `agent/config/conffile.go` and `agent/config/config.go`, with env vars only as an override. The conf-file path keeps the secret out of `launchctl print` output. Residual risk is bounded to local root-equivalent access or incorrect file permissions on the conf file. |
| Denial of service | MDM-driven mass uninstall. | Out of scope (the MDM is a trust anchor); the agent has no self-uninstall path. |
| Elevation of privilege | Pre / post-install scripts have a bug, run as root. | Scripts are minimal (write conf file, kickstart LaunchDaemon); reviewed; signed pkg gates execution. |

## Cross-cutting threats

### Supply chain

| Threat | Mitigation |
| --- | --- |
| Dependency compromise (Go module / npm package). | `govulncheck` (gating CI), OSV-Scanner (gating CI), CodeQL on Go + TypeScript + Swift, Dependabot weekly bumps with `cooldown`. |
| Build-process compromise (CI runner). | SHA-pinned actions everywhere; OIDC-keyless cosign signing means the signing key never lives on the runner; release-secrets-check workflow on every release. **GAP, medium**: no `step-security/harden-runner` egress firewall on CI jobs. |
| Malicious release tag pushed by a third party. | Branch-protection rule (env-gated `release-signing` allowed only for `v*` refs); release-secrets-check runs on every release. |
| Notarization gating bypass. | Apple verifies the notary ticket at install time; pkg without one prompts the user. |
| SBOM tampering. | SBOMs (CycloneDX + SPDX) are signed by cosign at the same time as the pkg; mismatched SBOM rejects verification. |

### Detection content

| Threat | Mitigation |
| --- | --- |
| A bad detection rule causes false-positive storm. | Per-rule unit tests in `server/rules/internal/catalog/<rule>_test.go` cover Evaluate against real event fixtures; the rules-context integration test (`server/rules/internal/tests/integration_test.go`) iterates every shipped rule and locks catalog + doc-shape invariants; `tools/gen-rule-docs` ensures every rule has documented severity + false-positive sources. |
| A missed detection allows attacker activity through. | Documented in [`detection-rules.md`](detection-rules.md) as "Limitations" per rule; ATT&CK coverage page surfaces the gaps. Future work: Atomic Red Team / Caldera replays in CI. |
| Inadvertent denial of service via inline blocking. | Application Control shipped (`server/rules/internal/operator/appcontrol_handler.go`, gated by the `application_control.*` chokepoint actions). It is operator-driven, versioned, and audited; there is no automatic blocking based on rule output (alerts emit; blocks require an explicit operator-authored policy pushed via the `set_application_control` command). A forged or buggy blocklist is bounded by operator-only authorship at the RBAC chokepoint plus versioning, so the failure mode is an auditable over-block (DoS) or under-block, never silent agent-originated enforcement. |

### Authentication and authorisation

| Threat | Mitigation |
| --- | --- |
| Credential phishing of an EDR operator. | Day-to-day login is OIDC with PKCE; the IdP enforces MFA upstream of the EDR. Break-glass at `/admin/break-glass` is WebAuthn-mandatory (no password-only fallback), phishing-resistant by design. The break-glass surface is gated by `EDR_BREAKGLASS_IP_ALLOWLIST` and per-IP + per-email rate limits; off-allowlist callers see a generic 404 (path existence is concealed). |
| Stolen session cookie. | Session cookies are HttpOnly + Secure + SameSite=Lax with idle (default 8h) and absolute (default 24h) caps; break-glass sessions are tighter (15m idle / 1h absolute). Destructive actions require a fresh re-auth (default 30m, `EDR_REAUTH_WINDOW`); the chokepoint denies stale-session attempts with a typed `reauth_required` reason that the UI converts into an inline reauth prompt. |
| Operator escalation past their role. | Every privileged HTTP route is gated by `api.HTTPGate`, an OPA-backed chokepoint that maps the request to a typed action and evaluates it against the actor's role binding. The current release ships five roles (`super_admin`, `admin`, `senior_analyst`, `analyst`, `auditor`); the binding source is the `role_bindings` table, populated by the OIDC JIT provisioner (default `analyst`, the lowest-privilege tier; an `admin` promotes via the Users page or SQL until a future release ships group mapping). Architecture tests (`server/identity/internal/authz/...`) gate every new HTTP handler on chokepoint coverage. |
| Compromise of a service-account credential or access token. | Non-human principals authenticate with the OAuth 2.1 client-credentials grant (ADR-0013): a long-lived credential (`client_id` + secret) is SHA-256-hashed at rest, shown once, and exchanged at `POST /api/oauth/token` for a short-lived (15 min) signed access token that is verified statelessly on every API request (signature + `exp` + audience, no DB read) and presented as `Authorization: Bearer`, CSRF-exempt because a bearer token is not an ambient credential. A leaked access token self-expires in 15 minutes; disabling or revoking the service account bumps its epoch so outstanding tokens stop validating within the per-replica revocation-snapshot refresh window and no new token can be minted. A service account is bound to a single role synthesized as one global binding and evaluated by the same OPA chokepoint as a human; `super_admin` is never bindable to a service account, and `admin` only at operator discretion (`server/identity/internal/saadmin`). Because a machine has no interactive session the actor is never marked session-fresh, and the destructive-action reauth gate is human-only, so a service account's destructive reach is decided solely by its bound role. |
| Suppression of a response action by an authorised-but-hostile operator. | Withdrawing a queued command (`POST /api/commands/{id}/cancel`) requires the same action the command's own type requires, not read access: preventing a response is itself a response decision, so an actor who can only observe a host cannot disable incident response on it. The withdrawal is gated by the same OPA chokepoint, recorded in `audit_events` with the command id and type, and only reaches a command no agent has taken. Once an agent has acknowledged one, withdrawal is refused, and a late acknowledgement for a command withdrawn in the delivery race reopens it, so the record reports what actually ran on the host rather than what the operator asked for. |
| Audit log tamper. | `audit_events` is enforced append-only: a build-time test (`server/identity/internal/audit/append_only_lint_test.go`) scans production source for any UPDATE or DELETE against `audit_events` and fails the build if one appears. Each successful row is dual-emitted to slog at INFO with the action + actor + payload attributes; failures (queue_full, drain_deadline_exceeded, INSERT errors) hit slog at WARN. Both flow through OTLP, so an in-server compromise that drops MySQL writes still leaves the OTel-side record. |
| Compromise of the OIDC client secret or the deployment root secret. | The OIDC client secret is entered in the Single sign-on settings UI and stored encrypted at rest in `oidc_config` (sealed with a key derived from `EDR_SECRET_KEY`); the server reads no `EDR_OIDC_*` env vars, so the client secret never appears in env-listing output. The deployment root secret is loaded via an `EDR_SECRET_KEY_FILE` path (Docker-secrets convention), also off env-listing output. Rotating the OIDC client secret in the UI takes effect without a restart; sessions stay valid because they are signed with a key derived from `EDR_SECRET_KEY` (a separate 32+ byte secret), not the client secret. Rotating `EDR_SECRET_KEY` invalidates every existing session (operators sign back in via OIDC), every host token (agents re-enroll automatically), and every service-account access token (clients re-run the client-credentials grant), since the cookie signing key, the host-token pepper, and the service-account token-signing key all derive from it (ADR-0013). A leaked `EDR_SECRET_KEY` therefore also lets an attacker forge service-account tokens, which concentrates rather than expands the existing host-token and session blast radius. |
| First-boot bootstrap-token leak. | The break-glass redemption URL is a one-shot bearer credential printed to stderr at first boot. TTL defaults to 1h (configurable); the token is stored as a SHA-256 hash, not plaintext. Re-printing the banner on every restart until redemption is by design: no leaked banner predates redemption. |

### Insider threat at the EDR vendor

| Threat | Mitigation |
| --- | --- |
| Malicious release pushed by a compromised maintainer. | Cosign keyless signing + SLSA L2 provenance ties every release to the workflow that produced it; branch protection on `main`; reviewed PRs. **GAP, medium**: no signed-commit policy, no `CODEOWNERS`, no required-review count enforced as code. |
| Backdoored dependency added to `go.mod` / `package.json`. | Reviewed PRs; Dependabot auto-bumps go through CI gates; `cooldown` window prevents fast-moving compromised versions from auto-merging. |
| Detection content silently regressed. | Per-rule fixture tests gate every PR; deletion of a fixture is itself a visible diff. |

## Known gaps with severity

Copied from the per-component tables for at-a-glance triage. Severity reflects pilot-deployment impact, not theoretical worst case.

**High**: block multi-seat pilots:

- (None remaining for v0.2.0 ship. The current OIDC + WebAuthn break-glass + chokepoint roles closed the prior MFA and RBAC gaps; per-team scoping inside a single deployment is a follow-on feature, not a v0.2.0 gap.)

**Medium**: block a security-mature pilot's procurement:

- Encryption at rest for the raw event archive in ClickHouse (component 7) and for the per-alert evidence copies in MySQL (component 6): a deployment-mode item, not enforced in code.
- `Content-Security-Policy` header on the UI (component 5).
- The server / ingest tier connects to MySQL and to ClickHouse as a broadly-privileged user; both need a least-privilege grant scoped to the EDR schema (components 6 and 7).
- `step-security/harden-runner` on CI jobs (supply chain).
- Signed-commit policy + `CODEOWNERS` + required-review-count (insider).

**Low**: operational hygiene:

- Per-host rate limits beyond per-route caps (component 4).
- Pagination contract on list endpoints (component 5).
- `edr.network.events.dropped` counter (component 3).
- No per-replica cap on concurrent agent control connections beyond the host population and OS limits (component 8).

## Out of scope

- **macOS kernel exploits.** SIP, KASLR, kernel signing, and Apple's response cycle own this. Outside the EDR's control surface.
- **Physical access to the endpoint.** A physically-present attacker with FileVault unlocked is not in this threat model; disk encryption and device-loss policy own that boundary.
- **Compromised MDM.** The MDM is a trust anchor; if it is itself compromised, the deployment chain is broken and the EDR cannot defend against its own legitimate-looking install.
- **Side-channel attacks.** Timing, cache, Spectre-class. Not in MVP scope.
- **Anti-forensic evasion at the OS level by an already-root attacker.** A privileged attacker who already has root can disable the sysext via `systemextensionsctl`. Detection of _that_ is the canonical "EDR tamper resistance" line item flagged at [`best-practices.md`](best-practices.md) §1.

## Revision policy

Update this document when:

- A new component is added to the architecture (a new daemon, a new service, a new API surface).
- A new trust boundary is crossed (a webhook out, a SIEM export endpoint, cross-deployment routing).
- A gap above is closed: move the bullet from "gap" to a citation in the per-component table.
- A new STRIDE category becomes relevant for an existing component (e.g., shipping RBAC opens new spoofing + elevation surfaces that need entries).

Last reviewed against the v0.2.0 release line on 2026-06-16, re-verifying the auth + authz model (OIDC, WebAuthn break-glass, chokepoint roles, reauth window) against the code, and covering the v0.2.0 host-token change: bearer tokens are now verified as HMAC-SHA256 keyed by a server-held pepper derived from the deployment root secret (`internal/keyring`), replacing the prior Argon2id-at-rest scheme. The change suits the high-entropy token (no offline brute-force concern) and removes the per-request Argon2id cost on the ingestion hot path while adding DB-leak resistance (the pepper is never stored). No new trust boundary or component was introduced.

Re-verified by a full code-driven boundary inventory on 2026-06-19. Changes this pass: Application Control is now shipped (not "under construction"), so the agent's command surface gained the `set_application_control` type carrying an operator-authored, versioned, audited blocklist (component 1 EoP + Detection-content rows updated); corrected the moved XPC source reference (`extension/edr/extension/XPCServer.swift` to `extension/edr/shared/XPCEventServer.swift`); and named OTLP telemetry export as an explicit egress trust assumption. Confirmed unchanged: the agent-to-server boundary is a per-host bearer token over server-side TLS 1.3 (not mTLS), and the medium/low gaps (events-at-rest encryption, CSP header, MySQL least-privilege user, CI harden-runner, signed-commit / CODEOWNERS / required-review) all still stand against current code.

Re-verified by a full code-driven boundary inventory on 2026-07-05 (v0.3.0 pre-release line). Three shipped changes since the last pass altered the boundary map. (1) ClickHouse event archive (ADR-0015): the raw `events` table left MySQL (`server/detection/migrations/00007_drop_events.sql`) for a private-network ClickHouse store owned by the new `visibility` context, adding a Server-to-ClickHouse persistence boundary (new component 7) and a matching trust assumption; MySQL now retains the control plane, process graph, ephemeral `event_queue`, alerts, and self-contained evidence copies, so the component 6 retention row (process records only; ClickHouse native TTL for events) and the at-rest row were corrected. (2) The single-port control channel (ADR-0016, issue #477): a bidirectional gRPC command-push stream multiplexed onto the same HTTPS listener, authenticated by the same host bearer token as the HTTP path with a 5s revocation re-check, added as new component 8 and named as the one sanctioned stateful tier (ADR-0010 amendment). (3) Service-account / API-token auth (ADR-0013) under the unified principal model (ADR-0017): a non-human actor class authenticating with short-lived self-validating bearer tokens through the same OPA chokepoint, added to the authentication-and-authorisation cross-cutting table. Also corrected a stale claim: TLS is now TLS 1.3 unconditionally, with no TLS 1.2 opt-out and no cipher-suite knob (`server/httpserver/tls.go`), replacing the doc's prior "TLS 1.2 with restricted AEAD suites" language. No threat was demoted out of scope; the medium/low gaps carried forward, re-homed to their current components (events-at-rest is now on ClickHouse, and MySQL-root least-privilege is now a MySQL-and-ClickHouse item).
