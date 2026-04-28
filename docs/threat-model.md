# Threat model

This document is Fleet EDR's threat model. It exists for three audiences:

1. **Engineers reviewing security-sensitive PRs** — "does this widen one of
   the listed threats? does it close a gap?"
2. **Pilot-customer security reviewers** asking what attack surface the
   vendor considered before installing the agent on managed endpoints.
3. **Future contributors** evaluating where investment is most needed.

Format is STRIDE per component, with each cell either citing the existing
mitigation or flagging a `GAP` with severity (high / medium / low) reflecting
pilot-deployment impact, not theoretical worst-case.

Scope is the system as it ships in the v0.1.0-rc.* line: Go agent + Swift
system extension + Swift network extension on macOS endpoints, Go server
with MySQL backend, embedded React UI, MDM-driven deployment. Out of scope
is everything in the closing section.

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
                              HTTPS (TLS 1.3)
                              Bearer host_token
                                     |
+------------------------------------v------------------------------------+
|                        Server (Go, distroless container)                 |
|  +-----------+  +-----------+  +-----------+  +-----------+              |
|  | Ingest    |  | Detection |  | Admin API |  | UI (embed)|              |
|  | API       |  | Engine    |  | (session) |  |  React    |              |
|  +-----+-----+  +-----------+  +-----+-----+  +-----------+              |
|        |              |              |              |                    |
+--------|--------------|--------------|--------------|--------------------+
         |              |              |              |
         +-----+--------+----+---------+----+---------+
               |             |              |
       MySQL (private)   OTLP (gRPC)   Browser session
                            |
                     OTel collector
```

Trust assumptions:

- **The MDM is a trust anchor.** It delivers the signed `.pkg` and the two
  configuration profiles (system-extension allowlist, network-extension
  allowlist). A compromised MDM is out of scope.
- **The endpoint kernel and Apple frameworks are trusted.** ESF, NEFD,
  launchd, SIP. Their integrity is Apple's responsibility.
- **The MySQL instance is on a private network.** Direct DB-network
  compromise is out of scope; anything past the Compose network is the
  operator's responsibility.

## Per-component threats

### 1. Agent daemon (Go, runs as root via LaunchDaemon)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Unprivileged process impersonates the agent over XPC to the sysext. | The sysext registers its Mach service via `NSEndpointSecurityMachServiceName` in `extension/edr/extension/Info.plist` (system-extension-side, not a LaunchDaemon `MachServices` entry). Every accepted peer is constrained by `xpc_connection_set_peer_code_signing_requirement` (see `extension/edr/extension/XPCServer.swift`) with the agent's expected team-ID code-signing requirement; connections that don't satisfy the requirement are dropped before any message is processed. |
| Tampering | Local attacker overwrites the agent binary or LaunchDaemon plist. | SIP protects the install path; the agent binary is Developer-ID-signed and notarized; modification breaks the signature and macOS refuses to launch. |
| Repudiation | Command lifecycle goes unlogged. | Every command transitions (`pending` → `running` → `success`/`failure`) are persisted both locally (slog) and server-side (`commands` table). Admin actions emit a WARN-level audit log line. |
| Information disclosure | Sensitive payload data leaks to the agent log. | `os.log` argv redaction; agent's slog handler does not print full event payloads at INFO level; sensitive fields stay at DEBUG (off by default). |
| Denial of service | SQLite queue grows unbounded, breaks the agent. | `EDR_AGENT_QUEUE_MAX_BYTES` enforces a cap; over-cap rows are dropped + counted in `edr.agent.queue.dropped` (with the `lossy` attribute distinguishing data loss from already-delivered trims). Documented in `docs/operations.md`. |
| Elevation of privilege | A network attacker uses the root-running agent to execute arbitrary code. | Agent only executes typed commands (`set_blocklist`, `kill_process`, etc.) fetched from the server, authenticated by the per-host bearer token. The command-type → handler mapping is exhaustive; unknown types are rejected. |

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
| Information disclosure | NE captures connection payload bytes. | Configured for **flow-handling-only** — 5-tuple + PID + signing context. Payload bytes are deliberately not captured. This sidesteps wiretap-law concerns and reduces the data-at-rest footprint. |
| Denial of service | NE's allow-or-deny verdict latency stalls all connections. | Verdicts are inline with a small per-decision budget; framework falls back to `verdictAllow` if the client extension is unresponsive. |
| Elevation of privilege | NE bug → root. | NE runs as root by Apple design; minimal surface; uses Apple-vetted `NEFilterDataProvider` API. |

### 4. Server (Go, distroless container)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Attacker enrolls a fake host or impersonates an enrolled one. | Enrollment requires the shared `EDR_ENROLL_SECRET` plus a hardware UUID; subsequent requests carry an opaque per-host bearer token (Argon2id-hashed at rest, deterministic token-id index for fast lookup). Tokens are scoped: events with `host_id ≠ token's host_id` are rejected. |
| Tampering | Attacker modifies events or admin actions in flight. | TLS 1.3 by default; TLS 1.2 only with explicit opt-in for legacy pilots, with restricted AEAD cipher suites. |
| Repudiation | Admin action goes unaudited. | Every admin endpoint emits a WARN-level slog line plus span attributes (`edr.admin.action`, `edr.admin.actor`, `edr.admin.reason`). Logs flow via OTLP to an external sink, so an in-server tamper cannot retroactively erase the trace export. |
| Information disclosure | Database or backup leak exposes credentials. | Passwords + host tokens Argon2id-hashed; DSN + enroll secret loaded via `_FILE` paths (Docker-secrets style) so they are never in env-listing output; TLS 1.3 over the wire; `subtle.ConstantTimeCompare` for CSRF token comparison. **GAP, medium**: encryption at rest for the events table is documented as a deployment requirement, not enforced in code. |
| Denial of service | Login or enroll endpoint flooded. | Per-IP rate limiting (`EDR_LOGIN_RATE_PER_MIN` default 6, `EDR_ENROLL_RATE_PER_MIN` default 30) returns `429 Too Many Requests` with `Retry-After`. Event ingestion is per-token, gated by enrollment. **GAP, low**: no per-tenant or per-host rate limit beyond the per-route caps. |
| Elevation of privilege | Browser-based attacker uses an admin session. | HttpOnly + Secure + SameSite=Lax session cookies; per-session CSRF token on every unsafe method; HSTS with `includeSubDomains`, two-year max-age; session secret is sanitized to a 256-char base64url charset on read/write. **GAP, high**: no MFA. **GAP, high**: no RBAC tiers — every authenticated user is admin. |

### 5. UI (React, embedded in server)

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Phished credentials. | Rate-limited login. **GAP, high**: MFA is not implemented. |
| Tampering | Cross-site scripting. | React's default JSX escaping; no `dangerouslySetInnerHTML` in the codebase; ESLint's `no-unsanitized` plugin gates PRs; CodeQL TypeScript SAST is wired. **GAP, medium**: no Content-Security-Policy header. |
| Repudiation | UI action not auditable. | Every state-changing action goes through a server endpoint with audit logging; the UI is a thin client. |
| Information disclosure | Wrong analyst sees the wrong alert. | Today every authenticated user sees everything (single admin tier). **GAP, high**: RBAC tiers (analyst / admin / read-only). |
| Denial of service | UI hammers the read API. | Read endpoints are session-cookie authenticated; clients are admin-controlled. **GAP, low**: no pagination contract on list endpoints. |
| Elevation of privilege | UI bug runs commands without authorisation. | Every privileged endpoint requires the session cookie (HttpOnly, JS-invisible) plus the CSRF header (JS-readable); CSRF tokens never live in cookies; React Router does not synthesize cross-origin requests. |

### 6. MySQL data plane

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Captured DSN reused. | DSN provided via Docker secret file (`EDR_DSN_FILE`); MySQL not exposed outside the Compose network. **GAP, medium**: server connects as MySQL root; should be a least-privilege user with grants only on the EDR schema. |
| Tampering | Direct DB writes that modify alerts or enrollments. | Only the server has the credentials; the server's writes are auditable. |
| Repudiation | Audit rows removed from `commands` / `enrollments`. | Server audit also emits to `slog` → OTLP → external sink, so a DB tamper does not erase the trace export. |
| Information disclosure | DB compromise exposes events / passwords. | Argon2id for passwords + host tokens. **GAP, medium**: no application-level encryption of event payloads at rest; relies on storage-layer encryption (InnoDB tablespace encryption, host filesystem encryption) which is a deployment-time choice. |
| Denial of service | Disk fills with events. | Retention runner (`EDR_RETENTION_DAYS`, default 30); per-batch DELETE with `LIMIT` keeps InnoDB lock footprint bounded; `edr.retention.rows_deleted` counter for the operator alert. |
| Elevation of privilege | SQL injection. | Parameterized queries throughout (no `fmt.Sprintf` into queries); golangci-lint `sqlclosecheck` and `noctx` rules; integration tests against a real MySQL 8.4 instance in CI. |

### 7. MDM and install path

| Category | Threat | Mitigation |
| --- | --- | --- |
| Spoofing | Attacker pushes a fake `.pkg` claiming to be the EDR. | Pkg is Developer-ID-signed and Apple-notarized; macOS verifies the signature at install; the `.mobileconfig` profile binds the team ID expected for the system extension. |
| Tampering | Malicious post-install scripts. | Pkg post-install scripts live in `packaging/pkg/` and are reviewable; build is via the signed CI release workflow; no `curl \| bash` at install time. |
| Repudiation | Install / uninstall not logged. | macOS records `/var/log/install.log`; agent enrollment logs the host's hardware UUID + first-seen time on the server side. |
| Information disclosure | Enroll secret leaks via process listing or shell history. | The pkg postinstall script (and Fleet's install-script contract — see `packaging/pkg/scripts/postinstall`) writes the enroll secret to root-owned `/etc/fleet-edr.conf`; the agent reads that file via the layering in `agent/config/conffile.go` and `agent/config/config.go`, with env vars only as an override. The conf-file path keeps the secret out of `launchctl print` output. Residual risk is bounded to local root-equivalent access or incorrect file permissions on the conf file. |
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
| A bad detection rule causes false-positive storm. | Per-rule unit tests; integration test in `all_rules_integration_test.go` exercises every shipped rule end-to-end; `tools/gen-rule-docs` ensures every rule has documented severity + false-positive sources. |
| A missed detection allows attacker activity through. | Documented in `docs/detection-rules.md` as "Limitations" per rule; ATT&CK coverage page surfaces the gaps. Future work: Atomic Red Team / Caldera replays in CI. |
| Inadvertent denial of service via inline blocking. | `set_blocklist` policy is operator-driven, version-bumped, audited; no automatic blocking based on rule output (alerts emit; blocks require explicit operator action). |

### Insider threat at the EDR vendor

| Threat | Mitigation |
| --- | --- |
| Malicious release pushed by a compromised maintainer. | Cosign keyless signing + SLSA L2 provenance ties every release to the workflow that produced it; branch protection on `main`; reviewed PRs. **GAP, medium**: no signed-commit policy, no `CODEOWNERS`, no required-review count enforced as code. |
| Backdoored dependency added to `go.mod` / `package.json`. | Reviewed PRs; Dependabot auto-bumps go through CI gates; `cooldown` window prevents fast-moving compromised versions from auto-merging. |
| Detection content silently regressed. | Per-rule fixture tests gate every PR; deletion of a fixture is itself a visible diff. |

## Known gaps with severity

Copied from the per-component tables for at-a-glance triage. Severity reflects
pilot-deployment impact, not theoretical worst case.

**High** — block multi-tenant or multi-seat pilots:

- MFA on the UI (component 5).
- RBAC tiers — analyst / admin / read-only (components 4, 5).

**Medium** — block a security-mature pilot's procurement:

- Encryption at rest for the events table (component 6, deployment-mode item).
- `Content-Security-Policy` header on the UI (component 5).
- Server connects as MySQL root; needs a least-privilege user (component 6).
- `step-security/harden-runner` on CI jobs (supply chain).
- Signed-commit policy + `CODEOWNERS` + required-review-count (insider).

**Low** — operational hygiene:

- Per-tenant / per-host rate limits beyond per-route caps (component 4).
- Pagination contract on list endpoints (component 5).
- `edr.network.events.dropped` counter (component 3).

## Out of scope

- **macOS kernel exploits.** SIP, KASLR, kernel signing, and Apple's response
  cycle own this. Outside the EDR's control surface.
- **Physical access to the endpoint.** A physically-present attacker with
  FileVault unlocked is not in this threat model — disk encryption and
  device-loss policy own that boundary.
- **Compromised MDM.** The MDM is a trust anchor; if it is itself
  compromised, the deployment chain is broken and the EDR cannot defend
  against its own legitimate-looking install.
- **Side-channel attacks.** Timing, cache, Spectre-class. Not in MVP scope.
- **Anti-forensic evasion at the OS level by an already-root attacker.** A
  privileged attacker who already has root can disable the sysext via
  `systemextensionsctl`. Detection of *that* is the canonical "EDR tamper
  resistance" line item flagged at `docs/best-practices.md` §1.

## Revision policy

Update this document when:

- A new component is added to the architecture (a new daemon, a new service,
  a new API surface).
- A new trust boundary is crossed (a webhook out, a SIEM export endpoint,
  multi-tenant routing).
- A gap above is closed — move the bullet from "gap" to a citation in the
  per-component table.
- A new STRIDE category becomes relevant for an existing component (e.g.,
  shipping RBAC opens new spoofing + elevation surfaces that need entries).

Last reviewed against the v0.1.0-rc.\* release line on 2026-04-28.
