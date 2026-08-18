# Changelog

Notable changes to Fleet EDR, newest first. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0).

## [Unreleased]

### Added

- **A host whose network capture has silently stopped is now shown as degraded, even while its agent reports itself healthy.** A macOS network extension provider can keep reporting that it is running after it has stopped delivering events, which leaves the host looking fine while its connection and DNS telemetry is missing. The Hosts page and the host's health details now flag this and name the provider to re-enable, which takes re-activating the extension on that host. The signal is raised after two hours with no events from that provider on a host that is otherwise active, and it clears by itself once capture resumes. A host that is idle, offline, or has that provider deliberately turned off is not flagged.
- **Host health now names each capture provider separately.** A host's health detail previously reported the network extension as a single condition, so when something stopped capturing it said only that something under the extension was wrong. It now lists the content filter and the DNS proxy in their own right, each with its own state and how long it has been in it, so you can see which telemetry stream a host has stopped collecting without reading the message text. A provider you have deliberately turned off is not listed at all.
- **A new Critical alert `EDR sensor could not be restored` tells you which hosts are actually still blind.** The `EDR sensor disabled` alert below is raised seconds after capture stops, before the agent's automatic repair has run, so it reads the same whether the host fixed itself half a minute later or never came back. This second alert is raised only once the repair has used up its attempts, and it names the provider to re-enable. Those hosts are not collecting that telemetry until someone restores it, usually by re-activating the extension on the host. A provider that is repaired automatically, or one you deliberately turned off, raises nothing.
- **Investigate the new High alert `EDR sensor disabled` (MITRE T1562.001).** It means a host's capture provider was switched off and had not resumed 5 seconds later, so the host stopped reporting that telemetry. Investigate even when the host now reads healthy: the agent restores the provider by itself after about 35 seconds, which clears the health warning but does not make the stop legitimate. Agent upgrades and a deliberately disabled DNS proxy do not alert.

### Fixed

- **A truncated process tree now says so; narrow the time range or use search to see the rest.** On a busy host the graph can return fewer processes than the window matched, and it previously gave no sign that any were missing, so an absent process was indistinguishable from a dropped one. It now states how many of the matching processes it is showing.
- **Kill process is pinned to the exact process it targeted.** The "Kill process" action now carries the selected process generation, and the agent refuses the kill (reporting a generation mismatch) if that PID was reused or replaced its running image between you selecting it and the command reaching the host, so a stale kill can no longer terminate an unrelated process. A process that replaced its own image earlier in its life, which every `zsh -c` one-liner does, is killed normally.
- **Alerts are no longer silently dropped while the server is catching up on process data.** A busy or briefly backlogged server could discard a finding instead of retrying it, losing that alert permanently and with nothing in the logs to show it happened. The DNS C2 beacon rule was the most exposed, because it waits the shortest time and its alerts are Critical. Affected detections now fire normally. No action is required, but alerts missed before this upgrade are not backfilled.

## [0.4.0] (2026-07-07)

Feature release on top of 0.3.0. A re-architected event store adds fleet-wide hunting (process, connection, and DNS search), a per-host event timeline, and flexible time navigation across the investigation views. Also new: every service-account action is now fully attributable, agent health shows on the Hosts page, and the groundwork for Windows agents lands (no change for a macOS-only fleet). Read the upgrade notes before upgrading: `EDR_CLICKHOUSE_DSN` is now required and the `EDR_OIDC_*` SSO variables are removed.

### Upgrade notes (action required)

- **ClickHouse is now required.** Set `EDR_CLICKHOUSE_DSN` (or `EDR_CLICKHOUSE_DSN_FILE`) and run a ClickHouse instance alongside MySQL; the server and ingest service will not start without it. The reference compose stacks (`docker-compose.quickstart.yml`, `docker-compose.prod.yml`, and the multi-replica stack under `packaging/`) provision it for you. This is a hard cutover with no data migration: pre-upgrade event history is not carried over, though alerts and their evidence are preserved.
- **The `EDR_OIDC_*` variables and `EDR_AUTH_ALLOW_NO_OIDC` are removed.** Configure SSO under **Admin settings -> Single sign-on** (the in-product path since 0.3.0). Existing SSO keeps working: the configuration seeded on first boot under 0.3.0 remains the source of truth. Setting the old variables is now ignored, not an error.

### Added

- **Fleet-wide search.** A new **Search** page hunts across every host for processes (by host, path, SHA-256, uid, or signing verdict), outbound connections (by remote address), and DNS lookups (by domain). Results link back into the host's process tree, and the process detail panel gains one-click "search all hosts" pivots on a path, hash, IP, or domain.
- **Host event timeline.** The host page gains a **Timeline** tab beside the process graph: a filterable, newest-first list of the host's process, connection, and DNS events for the selected window, cross-linked with the graph in both directions. When opened for an alert, it scopes to the alert's process chain.
- **Flexible time navigation.** The fixed range buttons become one time control with relative quick-picks (up to 7 days) and an absolute from/to picker, plus an activity histogram of process starts over the window that you can click to zoom into a spike.
- **Richer process tree.** Hovering a node shows its full command line and a code-signing verdict (Apple platform, Developer ID with team, ad-hoc, signed, or unsigned; ad-hoc and unsigned are ringed amber). Repeated identical sibling executions collapse into a single `×N` node that expands on demand.
- **Host identity header.** The host page opens with hostname, online/offline status, OS, agent version, last seen, source IP, event count, and enrollment date, with the raw host id kept copyable for log correlation.
- **Inline MITRE ATT&CK technique tags.** Technique ids now appear where you investigate (process tooltips, the detail panel, and alert-triggering timeline rows), each linking to the rule's documentation.
- **Alert triage on the alert header.** An alert's status and its acknowledge / resolve / reopen controls live on the alert header, so an alert with no associated process can finally be triaged from its page.
- **Self-contained alert evidence.** Alerts capture their full triggering events at creation, so the evidence stays readable after those events age out of retention.
- **Agent health on the Hosts page.** Each host reports a health status (healthy / degraded / unhealthy) with per-component conditions, surfacing the previously invisible case of a host that enrolls but whose sensor never activates (it now reads "needs attention").
- **The account email is no longer shown in the top bar.** The account menu shows only an avatar initial until opened, so the signed-in identity is not passively disclosed on a screen-share.
- **Windows agent groundwork.** First steps toward Windows support: events carry an operating-system platform, the Hosts page shows a Platform column, detection rules are scoped per platform, and the Windows agent collects process start/stop through a driverless (user-mode ETW) sensor. Additive; nothing changes for a macOS-only fleet.

### Changed

- **The app now opens on Alerts.** Signing in lands on the alert list instead of the host list, matching the alert-first workflow; the host list moves to its own **Hosts** page and the navigation reorders to Alerts, Hosts, Application control, Coverage. Update any bookmark of the application root, which now opens Alerts.
- **Service-account actions are fully attributable.** Every operator action is recorded against a typed principal (a user or a service account), so a service-account change names the specific account instead of appearing anonymous. Service accounts can now manage detection exclusions and rule settings, and the audit log and per-row attribution identify the acting principal for every entry.
- **Events are stored in a ClickHouse archive.** Ingested events now live in ClickHouse (the new search, timeline, and correlation features read from it), with retention as ClickHouse-native time-based expiry. This is the change behind the now-required `EDR_CLICKHOUSE_DSN` in the upgrade notes.
- **Host identity stays current without a re-enroll.** The agent's periodic check-in now carries the host's hostname, OS version, and agent version, and the server refreshes the host record from it, so a macOS upgrade, rename, or agent upgrade shows in the console within about a minute instead of staying frozen at enrollment time.
- **Alert and host page refinements.** The alert page drops the self-referential "related alert" link and quiets controls that would do nothing: an empty "Show system" toggle is hidden, and the "Kill process" button is disabled (with the reason shown) once the process has exited. Agent health moves into the host header's Details popover, with an attention dot only when a host is not healthy. Host and alert lists show the enrollment hostname rather than the raw hardware UUID.
- **Oversize mutation requests return 413.** The application-control and detection-config write endpoints now reject a request body past their size cap with `413 Request Entity Too Large` instead of a misleading parse error.

### Fixed

- **Detection alerts are no longer lost to a processing race.** Under concurrent event processing, a rule could evaluate an event before the batch carrying that process's exec had committed, treat the lookup miss as "no finding," and permanently drop the alert with nothing logged. Rule evaluation now retries when an event's process is not yet materialized. Affects the sudoers-tamper, keychain-dump, launchd-persistence, DYLD-injection, shell-from-Office, osascript, suspicious-temp-exec, DNS C2 beacon, and application-control detections.
- **Re-processing a batch no longer duplicates processes or alerts.** A batch retry that replayed the same fork/exec/exit events could duplicate process-graph rows, and the alerts keyed on them; the graph builder is now idempotent under replay.
- **Alert graphs render correctly with repeated siblings.** An alerted process that had identical-path siblings could be folded into the collapsed `×N` node and vanish from its own chain, rendering a blank graph; it now stays a first-class node. The collapse chevron on an expanded sibling group also no longer shows a stale state during search.

## [0.3.0] (2026-06-26)

Feature release on top of 0.2.1. The headline is operator self-service: detection tuning, single sign-on, API service accounts, and user management all move from boot-time environment variables into governed, audited admin screens that apply without a server restart. Also in this release: a clearer Hosts page, sharper persistence-attribution in alerts, several telemetry-delivery and on-device DNS reliability fixes, and a simpler, safer configuration surface.

### Upgrade notes (action required)

This release retires a number of `EDR_*` environment variables in favor of in-product configuration. Review these before upgrading:

- **Detection tuning is no longer set by environment variables.** The `EDR_*` variables that defined false-positive allowlists and disabled rules are removed. Re-enter any exclusions and per-rule settings through the new Detection settings screen (see Added). This is a hard cutover: suppressions not re-entered will no longer apply.
- **SSO is now configured in-product.** The `EDR_OIDC_*` variables now only seed the configuration on first boot; after that, the stored configuration is the source of truth and is edited from the Single sign-on settings screen.
- **Database connection is configured only via `EDR_DSN` / `EDR_DSN_FILE`.** The separate `EDR_MYSQL_*` variables are removed.
- **22 rarely used tuning variables are removed** and fixed as safe constants. Setting a removed variable is ignored rather than failing boot. The minimum TLS version is now unconditionally TLS 1.3. All security, compliance, and documented operational levers are retained.

### Added

- **Detection tuning moves to a governed admin surface.** View and edit false-positive exclusions and set each detection rule to alert, monitor (evaluate quietly without raising alerts), or disabled, from an audited UI and API. Changes take effect without a server restart and are scoped per host group where applicable.
- **Single sign-on settings screen.** Configure your OIDC identity provider (issuer, client ID and secret, scopes, and default role), test the connection before saving, and apply changes without a server restart. Just-in-time provisioning is always on: anyone who signs in through the provider is auto-created with the default role.
- **API service accounts.** Create non-human principals so automation, CI/release pipelines, and integrations can call the EDR API with a short-lived OAuth client-credentials bearer token instead of a human's browser session. Each account is scoped to a single role, rotated, and revoked from an admin screen, and every lifecycle action and token issuance is audited.
- **In-product user management.** Promote and demote operator roles and enable or disable accounts from a Users screen instead of editing the database by hand, with anti-lockout guardrails (the last admin cannot be demoted, you cannot change your own role, and break-glass users are protected) and an audit row on every change.
- **MITRE ATT&CK coverage map.** A ready-to-share ATT&CK Navigator layer, scoped to the macOS techniques the product detects, ships in the repo for handing to a buyer, auditor, or SOC analyst.
- **Runtime trace-sampling controls.** Tune the server's trace-telemetry volume from an audited admin API without a restart: cap high-frequency agent traffic, lift sampling fleet-wide during an incident-debugging window, and drop health-probe noise entirely. Aggregate latency and alerting keep reading from metrics, which are never sampled, so dialing traces down does not blind your monitoring.

### Changed

- **Redesigned Hosts page.** The page leads with a fleet summary (Online, Offline, and Total host counts) and identifies each machine by hostname and OS version rather than only its raw hardware UUID, so operators can recognize machines at a glance.
- **Single VM is the recommended deployment.** Stand up MySQL, the server, and a Caddy reverse proxy with automatic Let's Encrypt TLS on one operator-controlled VM with a single command. Managed-PaaS edges that run a content-inspecting WAF can silently block agent telemetry, so the supported getting-started path is one where you control the edge.
- **Reduced telemetry bandwidth and on-device overhead.** The agent now compresses uploads (gzip), cutting upload bandwidth several-fold, and repetitive network-connection and DNS-lookup events are coalesced into a single counted event before upload while preserving detection signal. On-device application-control allow decisions are cached at the kernel with safe invalidation on policy change, reducing CPU overhead during heavy process activity.
- **Smaller database footprint.** Per-process liveness heartbeat events (previously a large share of stored rows) are processed for freshness but no longer persisted, and two redundant indexes on the events table are dropped online with no downtime.
- **Fewer false positives from the suspicious-execution rule.** Parent-process allowlist entries now support `*` wildcards so a suppression survives a tool version upgrade, and a lookup to the host's own local DNS resolver no longer counts as a triggering connection. Lookups to public resolvers still fire.
- **Application-control policy changes apply reliably on large fleets.** Saving an application-control policy now pushes the new rules to assigned hosts in batched database writes instead of one write per host, so a change across hundreds or thousands of endpoints commits well inside the request budget instead of risking a timeout and a stuck save.

### Fixed

- **On-device DNS no longer wedges name resolution.** DNS forwarding now has timeouts and a self-healing watchdog that fails open (resolution keeps working) when no blocking policy is active, while still enforcing any active blocks. This fixes an incident where the DNS path could break all name resolution on an endpoint until a reboot, and the break-glass disable command no longer hangs.
- **Clear reboot prompt after a package upgrade.** Network and DNS coverage can stop after upgrading the installed package until the endpoint reboots; the product now surfaces an explicit "reboot required to restore network and DNS coverage" signal instead of an ambiguous warning.
- **Telemetry is retried, not discarded, when the edge rejects uploads.** When a proxy, WAF, edge, or unhealthy origin blanket-rejects uploads (for example with a 403), the agent keeps that telemetry queued and retries until the endpoint recovers, and emits a loud warning and metric so operators see the misconfiguration.
- **Alerts not tied to a single live process now explain themselves.** Persistence and similar alerts no longer open into a blank process graph; they show the alert description and MITRE technique tags with a clear explanation and an opt-in to widen to surrounding host activity.
- **More accurate exclusions and forensic attribution.** Detection exclusions now match correctly regardless of the macOS `/private` path form, so an allowlist you write takes effect; in multi-server deployments every replica picks up detection-config changes within seconds instead of serving stale config; and a network or DNS event from a process that re-launches itself is attributed to the correct generation in the alert timeline.
- **More accessible admin UI status messages.** The single sign-on connection-test result and the account-menu authentication-method badge now meet the WCAG AA color-contrast minimum, and the SSO status banners are emitted as semantic `<output>` live regions so assistive technology announces them.

### Removed

- **Render deployment support.** The one-click Render blueprint (`render.yaml`) and its guide are removed. Render's managed edge runs a content-inspecting WAF that blocks agent telemetry by default and cannot be disabled by the customer, so events silently fail to upload. Use the single-VM quickstart ([docs/quickstart-vm.md](docs/quickstart-vm.md)) instead, where you control the edge.

## [0.2.1] (2026-06-16)

Patch release on top of 0.2.0. Fixes the Mac-free Docker demo (`docker-compose.demo.yml`) so it presents correctly to evaluators. No agent or server runtime behavior changes; the fixes are confined to the demo seeder.

### Fixed

- **Demo process view stays populated across restarts.** On a restart against the persisted demo volume the seeder now slides the seeded timestamps forward, so the host process graph still falls inside the UI's default one-hour window instead of aging out and rendering empty. The shift is scoped to the demo's own hosts.
- **Demo alerts show a realistic process chain.** Woven attack scenarios are now re-parented under the captured host's interactive shell session instead of rooting directly at launchd, so an alert's process tree shows the full ancestry (for example `sshd -> zsh -> /usr/bin/security`) the way a real detection would.

## [0.2.0] (2026-06-16)

Incremental release on top of 0.1.1. Highlights: release signing modernized to the cosign v3 Sigstore bundle format, a detection-pipeline stall fixed, and the macOS system extensions now show recognizable names during a manual install.

### Added

- **Recognizable system-extension names.** The Endpoint Security and Network extensions now appear in macOS System Settings (Login Items & Extensions, Full Disk Access) as "Fleet EDR Security Extension" and "Fleet EDR Network Extension" instead of the generic "extension" / "networkextension", so an operator doing a manual (non-MDM) install can tell which Full Disk Access entry belongs to Fleet EDR.
- **Process-graph retention pruning.** The server prunes the process table on the configured retention window, bounding storage growth on long-running deployments.

### Changed

- **Modernized release signing (cosign v3).** Release artifacts are now signed as a single Sigstore bundle (`<file>.sigstore.json`) per file, and the server and demo-seed container images store their signatures and SBOM attestations as OCI 1.1 referring artifacts. Verify a download with `cosign verify-blob --bundle <file>.sigstore.json --certificate-identity-regexp ... --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
- **Pinned MySQL to 8.4.9** in the reference deployment stack.
- Updated UI build dependencies (esbuild, Vite, `@vitejs/plugin-react`).

### Fixed

- **Detection-pipeline stall on out-of-range UID/GID.** The process `uid`/`gid` columns are now `INT UNSIGNED`, so the macOS `nobody` account and the `KAUTH_UID_NONE` sentinel no longer overflow on insert; a single unpersistable event is isolated rather than wedging the whole detection pipeline.
- **Session-expiry handling.** The web UI redirects cleanly when a session expires instead of rendering affordances that then fail with 403.
- **OpenTelemetry noise.** Trimmed spurious telemetry output and tightened span/log scoping.

### Security

- **Hardened host enrollment tokens.** Host tokens are now verified with a keyed HMAC derived from a root secret.

### Observability

- Emit a `deployment.environment` resource attribute and scope the bundled SigNoz dashboards to it; added a dashboard filter plus render and metrics tuning.

### Documentation

- Tightened the install-server, MDM, and manual-agent deployment guides; led the README with deployment; documented the supported-version policy.

## [0.1.1] (2026-06-13)

First stable release. The product ships as two components, released together for now: the **macOS agent** (Apple Silicon, macOS 26+) and the **server** (a Linux container that runs anywhere containers do, cloud or on-prem). Core capabilities:

- **Real-time macOS endpoint monitoring.** An Endpoint Security system extension and a network extension capture process execution, fork/exit, file access, DNS queries, network connections, and background-task (launch item) registration, streamed continuously to the server.
- **Live process-graph correlation.** The server reconstructs a per-host process tree, including parent/child lineage and re-exec chains, so every alert carries the full process ancestry that led to it.
- **Out-of-the-box detection rules.** A catalog of behavioral detections covering credential access (keychain dumping), persistence (launch agents and daemons), privilege escalation (sudoers and launchd tampering), process injection (DYLD insertion), command-and-control beaconing, and suspicious execution chains.
- **Cross-stream correlation.** Rules reason over execution, DNS, and network together, catching multi-step behavior a single-signal tool misses, such as a process that beacons to a suspicious domain and then connects out.
- **Application control.** Block execution on the endpoint by binary hash, path, CDHash, signing ID, team ID, or leaf certificate, enforced at exec time before the process runs.
- **Process response.** Kill a running process on a host on demand from the server.
- **Tunable allowlists.** Per-rule allowlists suppress known-good management tooling, such as MDM agents that drop launch daemons or write sudoers, so legitimate activity does not generate noise.
- **Operator web UI.** Browse hosts, drill into process trees, triage and comment on alerts, and manage application-control policy.
- **SSO and break-glass authentication.** OIDC single sign-on with just-in-time user provisioning, plus a WebAuthn passkey break-glass path for recovery when SSO is unavailable.
- **Role-based access control.** Five built-in roles (super admin, admin, senior analyst, analyst, auditor) enforced through a single authorization chokepoint that no privileged action can bypass.
- **Append-only audit log.** Every privileged action and authorization decision is recorded immutably for later review.
- **Offline-tolerant agent.** A durable on-device SQLite queue buffers events when the server is unreachable and uploads them on reconnect, so nothing is lost during an outage.
- **Built to scale.** A stateless server runs as multiple replicas behind a load balancer, drains gracefully on deploy, applies schema migrations automatically, and enforces configurable event retention.
- **Flexible deployment.** The server is a standard Linux container image, so it runs on any container host (a Docker VM, Kubernetes, AWS ECS/EKS, GCP, Azure, or on-prem), with a one-click Render blueprint for the fastest start. Agents reach Macs through any MDM (Fleet, Jamf, Kandji, Intune, mosyle).
- **Supply-chain-hardened releases.** Every release ships a Developer ID-signed, Apple-notarized package alongside SBOMs, cosign signatures, and build provenance attestations.

[0.4.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.4.0
[0.3.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.3.0
[0.2.1]: https://github.com/getvictor/fleet-edr/releases/tag/v0.2.1
[0.2.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.2.0
[0.1.1]: https://github.com/getvictor/fleet-edr/releases/tag/v0.1.1
