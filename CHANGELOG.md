# Changelog

Notable changes to Fleet EDR, newest first. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0).

## [0.5.0] (2026-09-11)

Feature release on top of 0.4.0. The headline is rule content: the detection rules a deployment runs move out of the binary and into the database, so an upgrade delivers new rules, you can write your own through an audited API, and a rule set that turns out wrong can be rolled back. Also in this release: per-rule match counts and cost in the detection-tuning table, capture-provider health per host, a new alert for destruction of sudo policy, and a long list of detection-accuracy fixes.

### Upgrade notes (action required)

- **Upgrade your agents.** Two fixes land on the endpoint: process events are now stamped from the system's own event time rather than from when the agent finished handling them, and an agent that loses its control connection reconnects instead of waiting. The server tolerates the old stamps, so a host on an older agent already stops missing most of the connection detections described under Fixed; upgrading removes the cause rather than compensating for it, and is the only way to get the control-channel fix.
- **Reboot each Mac after upgrading its agent.** An in-place upgrade installs the new network extension, but macOS keeps the previous one registered until the machine restarts, so the agent cannot reach it: network and DNS telemetry stop while process events keep flowing. The usual health indicators are misleading here, since the extensions still show as activated and the host keeps checking in. What does show it is a repeating `xpc_bridge_connect failed for group.com.fleetdm.edr.networkextension` warning in `/var/log/fleet-edr-agent.log`, alongside connection and DNS detections going quiet. Measured upgrading 0.4.0 to 0.5.0 on real hardware.
- **Each server start now installs the rules that ship with the build.** Rule content used to be seeded once and never replaced, so an upgraded server kept running the rules it first installed. Rules you wrote and tuning you applied are untouched, but expect the rule list to change on the first start after upgrading.
- **`Suspicious exec chain` gives up one class of detection to make the rest tunable.** A chain whose parent is missing from the host's process tree used to alert naming the parent `(unknown)`, which no parent exclusion could suppress. Those chains now raise nothing. Chains started by `launchd` still alert and now name `/sbin/launchd`, so an exclusion for them works, and silences every launchd-started chain for that rule.
- **Exported rule files have a different shape.** `GET /api/rules/{id}/export` now carries the logic a rule matches on. What the rules detect is unchanged; re-check anything that parses the export.

### Added

- **Destroying sudo policy is now detected.** Emptying `/etc/sudoers` (or a fragment under `/etc/sudoers.d/`) and deleting one both raise a new `Sudoers policy destroyed` alert. Neither produced any telemetry before: emptying a file through a shell redirect is a different operation from writing to it, and the endpoint was not watching for it. The new alert is separate from `Sudoers tamper` because the two mean opposite things: one grants root access, the other takes access away and removes the record of what was there.
- **Detection rules are stored in the database and picked up without a restart.** They are seeded on first start from the release's own set, and each server re-reads within about thirty seconds of a change. A running server keeps its current rules when new content cannot be used, but a server starting up has nothing to keep and falls back to the release's rules: while unusable content is stored, a restarted server can be running different rules from its peers.
- **You can write your own detection rules through the API.** Create, replace, and delete rule files under `/api/v1/rule-content/documents`. A rule is checked with the same loader the server runs, so a change that would stop your rules loading is refused; `POST /api/v1/rule-content/documents:check` reports what a change would do without making it. Every change requires a reason and is audited with the document and who made it, and new rules start in monitor mode. Editing requires admin, viewing admin or senior analyst. Your rules are credited to your deployment rather than to the community project the shipped rules come from.
- **A rule that is too broad or too slow is caught when you submit it.** A search with no narrowing condition is flagged by name, because a rule resting on one fires constantly and buries the alerts you care about. It warns rather than rejects, since only you know whether you meant it. A pattern too expensive to match against every event is refused outright, naming the field to fix.
- **You can roll back a bad rule set.** Check whether you are running this build's rules, see which were added, removed, and changed, and put the previous set back. A rollback sticks across a restart, while the next release installs normally. Rules you wrote are kept either way, and you are told which shipped rules the rollback did not restore. One previous set is kept, and every rollback needs a reason and is audited.
- **The detection-tuning table shows what each rule has been matching and what it costs.** Each row reports matches over the last 7 days and how many hosts they came from, next to the control that promotes the rule, plus what its evaluations have cost: the total for the window, with the average per run beside it. Read matches as volume rather than as a count of alerts: repeated matches on the same process collapse into one alert. Both honor `EDR_RETENTION_DAYS` and start accumulating on upgrade. The Observed and Cost columns abbreviate, and the exact counts, the evaluation window and the worst-case duration open on click, tap or keyboard rather than on hover alone, so they are reachable without a mouse. Per-rule latency percentiles are also published as a metric.
- **A rule that is consistently too slow is dropped on the server that measured it.** One expensive rule used to slow detection for every rule on that server, with nothing to say which. It is now named in the logs and in a counter with what it measured, every other rule keeps running, and a restart gives it another chance. Nothing shipped in this release comes close to the budget.
- **Host health names each capture provider, and flags one that has stopped silently.** The content filter and the DNS proxy are listed in their own right, each with its own state and how long it has been in it. A provider that still reports itself running but has delivered no events for two hours on an otherwise active host is shown as degraded and named; it clears by itself once capture resumes. A provider you turned off deliberately is not listed.
- **Two alerts for a sensor that stopped capturing.** `EDR sensor disabled` (High) is raised when a provider stops and does not come back within 5 seconds, which is what separates a real stop from the brief gap an agent upgrade leaves. It does not say who stopped it, and it is worth investigating even once the host reads healthy, because the agent's automatic repair clears the health warning without making the stop legitimate. `EDR sensor could not be restored` (Critical) is raised only once that repair has used up its attempts, and names the provider to re-enable: those hosts are blind until someone restores them.
- **A command can be cancelled, and one that waits too long is dropped instead of running late.** A command queued for an unreachable host used to stay pending indefinitely and run whenever the host came back. That is a real risk for Kill process, since PIDs get reused. Cancelling requires the same permission as issuing, and undelivered commands now show as cancelled or expired rather than as failures.

### Changed

- **The `dns_c2_beacon` rule is now called "Suspicious process phoning home".** It never detected beaconing: it looks for a program launched from a temporary or world-writable folder that resolves a domain and then connects to the address that lookup returned, with no measurement of periodicity. The old name suggested beaconing was covered, and that alerts had observed a repeating pattern; neither was true. The rule identifier is unchanged, so existing exclusions and per-rule settings keep working and historical alerts are unaffected. Alert titles raised from now on carry the new name.

### Fixed

- **Detections that tie a network connection to the process behind it no longer miss fast activity on busy hosts.** Process events were stamped up to 0.7 seconds late under load, so a connection could appear to happen before the process that made it and the detection stayed silent: quick scripted activity was missed while slower activity was caught. Agents now stamp from the system's own event time, and the server tolerates a small amount of this skew, so hosts on an older agent improve too.
- **`Suspicious exec chain` now catches payloads it used to miss entirely.** A command run through `zsh -c` was invisible while the identical command under `bash` or `sh` alerted, because on macOS zsh replaces itself with the payload rather than starting it as a child. A payload behind two layered shells was judged by the outermost, which is often too old for the rule's 30-second window. Both now resolve to the shell that started the payload.
- **Alerts are no longer dropped while the server is catching up on process data.** A busy or briefly backlogged server could discard a finding instead of retrying it, losing that alert permanently with nothing in the logs to show it. `Suspicious process phoning home` was the most exposed, because it waits the shortest time and its alerts are Critical. Alerts missed before this upgrade are not backfilled.
- **A host whose events cannot be processed no longer stops reporting detections indefinitely.** A batch that failed the same way every time was retried forever, and because a host's events are processed in order, every rule stopped seeing that host, indistinguishable from one that had gone quiet. Such a batch is now given up on after roughly fifteen minutes and counted per host so you can alert on it; the events stay searchable. A read failure is retried rather than treated as a broken rule, and a detection whose name was too long to store no longer wedges the hosts it matches. Affected hosts resume on upgrade.
- **Alerts name the right binary for a process that replaced its own image.** If a process spawned something and then ran a different binary before the batch was evaluated, the alert could name the later binary, and a rule looking for a suspicious parent could miss it entirely. Relatedly, Kill process now refuses a PID that was reused or re-executed rather than killing the wrong process: re-select the process and retry.
- **A process's Network tab shows the connection its alert fired on.** Short-lived processes read "No network activity" even when an outbound connection was the reason for the alert, because the connection reaches the server after the process has exited. Connections and DNS lookups are now matched to the exact process that made them, so they also stop appearing under a different process that shared a PID.
- **Lowering a rule's severity no longer flattens the findings it had singled out.** `DNS beacon to a suspicious domain` rates a finding higher when the domain looks algorithmically generated, and setting the rule's severity used to overwrite that rating, so at low a high-entropy phone-home read the same as an ordinary one. Your setting now moves the whole rule and keeps the escalation on top of it.
- **Detection no longer slows down as you add servers.** Recording what each rule cost happened once per batch against the shared database, which set the ceiling on how fast the fleet's events could be processed. That ceiling is gone. Separately, a batch that outlived its five-minute lease is no longer completed by two servers at once, which could double-count a rule's matches.
- **`fleet-edr-migrate` applies every MySQL migration, not all but one.** The tool reported success having skipped one component's tables, so a deployment that runs migrations as a privileged step and then starts the server without schema-change permission failed on start, with nothing in the output to explain why.
- **Alerts a rule had already found survive a database outage.** When a lookup a rule depends on fails, the batch is retried rather than dropped. Until now the retry discarded whatever that rule had already found, so if the outage lasted long enough for the batch to be given up on, those detections were lost rather than delayed. They are now kept and raised. The retry also stops re-reading a dependency that has just failed once per event, which removed a burst of load landing on a database that is already in trouble.
- **Pasting a list of certificate hashes or paths into an application-control policy now works.** The paste-many flow labelled the `CERTIFICATE` and `PATH` rule types "coming soon" and refused to submit any line it inferred as one, even though the same rules could be created one at a time in the add-rule dialog and the server has always accepted them. Operators importing a mixed list had to change those lines to a different type or remove them.
- **The event timeline says so when the process tree could not be loaded at all.** It used to fall back to listing the whole host with no note, so the graph reported an error while the timeline beside it looked like a successful unscoped view. It now says the tree could not be loaded, rather than claiming the alert's process is absent from a tree that never loaded.
- **The event timeline now says when it could not narrow to an alert's chain.** Opening an alert's timeline shows only that alert's processes, but it can only do that for processes carrying the generation identifier it matches on. Where none of them do it lists the whole host, which is why a four-process graph could sit beside a timeline of everything with nothing to explain the difference; where only some do, it lists a partial chain while looking complete. It now says which of these you are looking at. Which events are listed is unchanged.
- **The ATT&CK coverage page names techniques and groups them by tactic.** It showed most of them as "Unmapped" with the bare technique id for a name: the page carried a hand-maintained list of 12 techniques while the rules covered 65. It now reads from the published ATT&CK data, so all 65 are named and grouped under the current tactics (v19 replaced Defense Evasion with Stealth and Defense Impairment, which the old list predated). The count of techniques covered only by silent rules stays, and now links to where you tune them: most of the shipped catalog records without alerting, so reading the "alerting" figure alone overstates coverage by about five times.
- **The application control policy list shows how many rules each policy holds.** It showed a dash for every policy, so telling which ones hold any rules meant opening each in turn.
- **The Mac-free demo tells a coherent story.** Its application-control alert now cites a policy rule that exists rather than a name nothing else uses, and its replayed processes carry the generation identifier an alert timeline needs to narrow to the alerting process's own chain.
- **Smaller fixes.** Exporting a rule you have written over a shipped one returns your file rather than the shipped one. Submitting a rule reports only what concerns the rule you changed, instead of every vendored rule this sensor cannot run. `Dylib injection via DYLD_INSERT_LIBRARIES` understands options before the assignment, such as `env -i`, and no longer treats unsetting a variable as setting it, while its sibling `DYLD injection on exec` stops claiming to catch a shell-assignment form the sensor cannot see, so the coverage you credit it with matches what it does. A process tree showing fewer processes than matched now says so. Alerts raised by a community rule before this release are credited to its author on the next server start.

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

[0.5.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.5.0
[0.4.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.4.0
[0.3.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.3.0
[0.2.1]: https://github.com/getvictor/fleet-edr/releases/tag/v0.2.1
[0.2.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.2.0
[0.1.1]: https://github.com/getvictor/fleet-edr/releases/tag/v0.1.1
