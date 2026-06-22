# Server Detection Rules Engine Specification

## Purpose

The detection rules engine is the analytic layer that turns the materialized process graph and raw event stream into behavioral alerts. It runs operator-curated rules against each batch of events that the processor releases, persists the resulting findings as alerts, and exposes them to the UI through the read API.

The capability owns the contract for what an alert is: how a rule firing maps to a row in the alerts table, how repeated firings of the same rule against the same process collapse to a single record, how MITRE ATT&CK technique mappings travel with each alert, and how a rule failure interacts with the rest of the batch.

## Requirements

### Requirement: Evaluate every registered rule against each batch

The system SHALL evaluate every rule that has been registered with the engine against each batch of events the processor delivers. A single rule MAY emit zero, one, or many findings per batch.

#### Scenario: A batch produces multiple findings from one rule

- **GIVEN** a batch of events that satisfies a rule's pattern in two distinct contexts
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the rule emits two findings
- **AND** both findings are persisted as separate alert rows

#### Scenario: A batch produces no findings from any rule

- **GIVEN** a batch of events that does not satisfy any registered rule
- **WHEN** the engine evaluates all rules against the batch
- **THEN** no alerts are persisted for that batch

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch: `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, and `dns_c2_beacon`.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, and `dns_c2_beacon`

### Requirement: Persisted alert schema

The system SHALL persist each finding as an alert that carries a host identifier, a rule identifier, a severity (`low`, `medium`, `high`, or `critical`), a human-readable title, a human-readable summary or description, an OPTIONAL linked process identifier, and the list of MITRE ATT&CK technique identifiers that the firing rule maps to. The process identifier is present when the finding is attributable to a live process and absent for process-less findings (for example a Background Task Management persistence registration, whose attacker has no live process at registration time).

#### Scenario: A rule fires and creates an alert

- **GIVEN** an event batch that satisfies one rule's pattern against a known process
- **WHEN** the engine evaluates the rule and persists the finding
- **THEN** the resulting alert row carries the host id, rule id, severity, title, description, linked process id, and technique list of the firing rule

#### Scenario: An alert with no attributable process omits the process link

- **GIVEN** a finding produced with no attributable process (a process-less finding)
- **WHEN** the engine persists the finding as an alert
- **THEN** the resulting alert row carries no linked process identifier and still records the host id, rule id, severity, title, description, and technique list

### Requirement: Alert dedup by subject

The system SHALL deduplicate alerts on the tuple (source, host id, rule id, subject), where the subject is a stable identity for the finding: for a process-backed finding the subject is its process identifier (preserving the historical (host, rule, process) dedup), and for a process-less finding the firing rule supplies the subject (for example the registered launch item). Re-evaluating a rule that yields the same subject on the same host in a later batch MUST NOT create a second alert row; the existing alert remains the single record for that finding.

#### Scenario: A rule re-fires on the same process in a later batch

- **GIVEN** an existing alert for a (host, rule, process) triple
- **WHEN** a later batch causes the same rule to find the same process again
- **THEN** the existing alert row is reused and no new alert row is inserted

#### Scenario: Process-less findings dedup on a rule-supplied subject

- **GIVEN** an existing alert for a process-less finding whose subject is its registered item
- **WHEN** a later batch causes the same rule to yield the same subject on the same host
- **THEN** the existing alert row is reused, while a finding with a different subject produces a distinct alert

### Requirement: Alert-to-event linkage

The system SHALL record the set of triggering event identifiers for each alert so that the read API can return them on the alert detail endpoint and analysts can pivot from the alert to the underlying telemetry.

#### Scenario: An analyst opens an alert and sees its triggering events

- **GIVEN** a persisted alert produced from a batch of events
- **WHEN** the alert detail is requested
- **THEN** the response includes the list of `event_id` values that caused the rule to fire

### Requirement: MITRE ATT&CK technique stamping

The system SHALL stamp each persisted alert with the MITRE ATT&CK technique identifiers declared by the firing rule. The stamped list MUST be preserved on the alert row even if the rule's technique mapping is later refined.

#### Scenario: A rule advertises ATT&CK techniques

- **GIVEN** a rule that declares technique identifiers such as `T1059.002` and `T1105`
- **WHEN** the rule fires and an alert is persisted
- **THEN** the alert row carries those technique identifiers
- **AND** subsequent edits to the rule's technique mapping do not modify the historical alert's stamped list

### Requirement: Rule failure isolation, batch retry on persistence failure

The system SHALL isolate a single rule's evaluation failure so that other rules in the batch still run. The system MUST NOT silently drop alerts on persistence failures: when persisting a finding fails, the batch is surfaced as failed so the processor can retry it.

#### Scenario: One rule errors during evaluation

- **GIVEN** a batch where one registered rule's evaluation returns an error
- **WHEN** the engine processes the batch
- **THEN** the error is recorded and the engine continues evaluating the remaining rules
- **AND** the remaining rules' findings are persisted normally

#### Scenario: An alert persistence write fails

- **GIVEN** a finding that the engine attempts to persist
- **WHEN** the persistence layer returns an error
- **THEN** the engine signals the failure to its caller so the entire batch is retried on a future cycle
- **AND** the failed finding is not silently discarded

### Requirement: Snapshot exec events are excluded from rule evaluation

The system SHALL exclude `exec` events flagged as snapshot from rule evaluation. Such events describe processes that existed before the agent began subscribing and represent historical state, not new attacker activity.

#### Scenario: A snapshot exec is delivered in a batch

- **GIVEN** a batch containing one or more `exec` events with the snapshot flag set
- **WHEN** the engine evaluates rules against the batch
- **THEN** the snapshot-flagged events are not visible to any rule
- **AND** no alerts are produced from those events even when they would otherwise match a rule's pattern

### Requirement: Operator toggling of individual rules

The system SHALL allow an operator to set an individual rule's mode to one of `alert`, `monitor`, or `disabled` through the durable detection-configuration surface (persisted in MySQL, edited via the admin API/UI), NOT through boot-time environment configuration. The mode MAY be set at global scope or scoped to a host group, and resolves per host most-specific-wins (a host-group setting overrides the global setting for hosts in that group). A rule that resolves to `disabled` for a host MUST NOT produce alerts for that host. A rule that resolves to `monitor` for a host MUST evaluate but MUST NOT persist an alert, emitting an observability signal instead so the would-be detection is visible without alerting. A rule that resolves to `alert` produces alerts as normal. A mode change MUST take effect without a server restart. A rule whose global mode is `disabled` MUST remain visible in the rule catalog surface (`GET /api/rules`) with its mode indicated rather than being removed from the catalog.

#### Scenario: An operator disables a noisy rule for their environment

- **GIVEN** a running engine and an operator who sets a rule's global mode to `disabled` through the detection-configuration API
- **WHEN** a batch arrives that would otherwise satisfy that rule
- **THEN** no alerts are produced for that rule
- **AND** the remaining rules continue to evaluate normally
- **AND** the disabled rule is still listed by `GET /api/rules`, marked disabled
- **AND** the change took effect without a server restart

#### Scenario: A rule set to monitor evaluates without alerting

- **GIVEN** a rule whose global mode is set to `monitor`
- **WHEN** a batch arrives that satisfies the rule for a host
- **THEN** no alert is persisted for that rule and host
- **AND** an observability signal records that the rule matched

#### Scenario: An operator re-enables a previously disabled rule

- **GIVEN** a rule whose global mode was previously set to `disabled`
- **WHEN** the operator sets its mode back to `alert` through the API
- **THEN** subsequent batches that satisfy the rule produce alerts again without a server restart

### Requirement: DNS-correlated C2 beacon detection

The system SHALL register a `dns_c2_beacon` rule that fires when a suspicious process resolves a domain and then connects to the resolved address, correlating all three telemetry streams. The rule MUST require, for a single originating process: a `dns_query` event carrying one or more `response_addresses`, and a subsequent `network_connect` event whose `remote_address` is one of those `response_addresses`, both within a bounded time window for that process. Address matching MUST be performed on parsed/normalized IP values (not raw strings) so that equivalent IPv6 forms compare equal. When several `dns_query` events for the process match the connection's `remote_address`, the rule MUST select the most recent matching query (deterministic tie-break by query name) for finding attribution.

The rule MUST gate on a suspicion signal derived from the originating process's exec context (for example an exec from a temporary or world-writable path, or a script interpreter with a non-interactive parent) so that ordinary browser traffic that resolves and connects to a domain does NOT fire. When the resolved domain also matches a domain-anomaly signal (a high-entropy or algorithmically-generated name), the rule MAY raise the finding severity and MUST add the `T1568.002` technique.

A firing alert SHALL cite the `dns_query` and `network_connect` events that compose the chain and SHALL be attributed to the originating process (its exec), so an analyst sees the full exec-to-DNS-to-network chain and the engine's per-process dedup collapses repeated beacons into a single alert. The rule MUST hold no state between batches; the correlation is performed by retrospective graph reads.

#### Scenario: A suspicious process resolves a domain and connects to the resolved address

- **GIVEN** a process exec'd from a temporary path that issued a `dns_query` for a high-entropy domain whose `response_addresses` include `203.0.113.10`
- **WHEN** a `network_connect` event for the same process to `remote_address` `203.0.113.10` is evaluated, within the correlation window
- **THEN** the engine produces one `dns_c2_beacon` finding
- **AND** the finding cites the `dns_query` and `network_connect` event identifiers
- **AND** the finding is attributed to the originating process (its exec)
- **AND** the finding carries the `T1071.004` technique, plus `T1568.002` because the domain tripped the anomaly signal

#### Scenario: A browser resolving and connecting to an ordinary domain does not fire

- **GIVEN** a browser process that issued a `dns_query` for an ordinary domain and connected to one of its `response_addresses`
- **WHEN** the `network_connect` event is evaluated
- **THEN** the engine produces no `dns_c2_beacon` finding, because the originating process does not satisfy the suspicious-exec-context gate

#### Scenario: A suspicious process that connects to an address it never resolved does not fire

- **GIVEN** a process exec'd from a temporary path that issued a `dns_query` resolving to `203.0.113.10`
- **WHEN** the same process emits a `network_connect` to `198.51.100.7`, an address that appears in none of its `dns_query` `response_addresses`
- **THEN** the engine produces no `dns_c2_beacon` finding, because the resolve-then-connect join is not satisfied

### Requirement: Path exclusions match across the macOS /private firmlink boundary

A detection exclusion of match type `path_glob` or `parent_path_glob` SHALL suppress a matching finding regardless of whether the candidate path is expressed in the public form (`/etc`, `/var`, `/tmp`) or the `/private`-prefixed firmlink form, because macOS resolves the two as the same file and ESF may report either. The operator-entered glob is matched against both macOS forms of the concrete candidate path; the glob itself MUST NOT be rewritten (a glob such as `*/claude/versions/*` cannot be canonicalized), and a candidate path under none of the aliasable prefixes is matched once with no extra cost.

#### Scenario: An exclusion matches the aliased form of the candidate path

- **GIVEN** a `path_glob` exclusion an operator wrote as `/etc/sudoers`
- **WHEN** a rule evaluates a candidate path that ESF reported as `/private/etc/sudoers`
- **THEN** the exclusion suppresses the finding
- **AND** the reverse holds: an exclusion written as `/private/etc/*` suppresses a candidate reported as `/etc/sudoers`

### Requirement: Detection configuration converges across replicas

Each server replica SHALL converge its in-memory detection-config snapshot with mutations made on other replicas without a restart. A mutation bumps a shared monotonic version counter; every replica periodically polls that counter and reloads its snapshot when the stored version has advanced past the loaded snapshot's, so an exclusion or rule-mode change made through one replica takes effect on every replica within the refresh interval. The poll reads only the single-row version counter, so a steady state with no configuration churn costs one indexed read per interval per replica.

#### Scenario: A replica adopts a configuration change made on another replica

- **GIVEN** two replicas sharing one database, each holding a loaded detection-config snapshot that excludes nothing
- **WHEN** an operator creates an exclusion through one replica
- **THEN** the other replica reloads its snapshot on a subsequent refresh tick
- **AND** begins suppressing the matching finding without a restart and without a mutation of its own

### Requirement: Durable detection configuration surface

The system SHALL persist detection-rule configuration (per-rule mode, optional severity override, per-rule settings, and false-positive exclusions) as durable state in MySQL, edited through the authenticated admin API and UI. Detection configuration MUST NOT be sourced from boot-time environment variables. Every mutation MUST pass through the RBAC authorization chokepoint and record an audit entry naming the actor. Each configuration record MAY carry a host-group scope (or be global); records also support an optional expiration after which they no longer apply. A configuration change MUST become effective for subsequent evaluations without a server restart.

#### Scenario: An operator adds a false-positive exclusion without restarting

- **GIVEN** a rule that is currently producing a benign finding for a known-good process
- **WHEN** an operator adds an exclusion for that rule (by a typed match such as a parent-path glob or a signing team ID) through the detection-configuration API
- **THEN** the exclusion is persisted in MySQL with the actor recorded in the audit log
- **AND** subsequent batches no longer produce that finding, without a server restart

#### Scenario: An expired exclusion stops applying

- **GIVEN** an exclusion whose expiration timestamp is in the past
- **WHEN** the engine evaluates a batch that the exclusion would otherwise suppress
- **THEN** the exclusion does not apply and the finding is produced

### Requirement: Per-host resolution of exclusions and rule settings

The system SHALL resolve detection exclusions and per-rule settings per host at evaluation time. Before a rule produces a finding for a given host, the engine MUST suppress that finding when an exclusion of the relevant match type applies to the host, where an exclusion applies if its scope is global OR a host group the host belongs to, and it has not expired. An exclusion scoped to a host group MUST NOT suppress findings for hosts outside that group. Per-rule mode and severity override MUST resolve most-specific-wins (host-group scope overrides global scope) for the finding's host.

#### Scenario: A host-group-scoped exclusion does not affect other hosts

- **GIVEN** an exclusion for a rule scoped to a specific host group
- **WHEN** the rule's pattern is satisfied on a host that is NOT a member of that group
- **THEN** the finding is still produced for that host

#### Scenario: A global exclusion suppresses the finding on every host

- **GIVEN** an exclusion for a rule at global scope
- **WHEN** the rule's pattern is satisfied on any host
- **THEN** the finding is suppressed for that host

### Requirement: Process-optional alert provenance correlation

For an alert that is not attributed to a single process (a process-optional finding such as a LaunchDaemon registration, persisted with `process_id = 0`), the system SHALL, when serving the alert detail, attempt to correlate the alert to the processes genuinely related to the detected artifact and return them as a set of related processes, each tagged with its role. Correlation MUST be performed at read time (alert-detail compose), MUST NOT alter the alert's persisted `process_id` or dedup identity, and MUST degrade gracefully to an empty set when no correlation is found.

For a LaunchDaemon/LaunchAgent registration finding the system SHALL derive related processes from the finding's linked registration event by:

- correlating the registered plist path to the nearest-preceding write-mode `open` event on that path for the same host, resolving the writing PID to a process and tagging it `artifact_writer`; and
- correlating the registered executable path to that executable's own process runs on the host, tagging them `persisted_executable`.

#### Scenario: Writer is correlated to a LaunchDaemon registration

- **GIVEN** a process-optional `privilege_launchd_plist_write` alert whose plist path was written by an observed process captured as a write-mode `open` event
- **WHEN** the operator requests the alert detail
- **THEN** the response includes the writing process among the related processes tagged `artifact_writer`

#### Scenario: No provenance is available

- **GIVEN** a process-optional alert whose plist was not captured as a write-mode `open` event (for example an atomic-rename write) and whose registered executable has no observed process run
- **WHEN** the operator requests the alert detail
- **THEN** the response returns an empty related-process set rather than an error
- **AND** the alert's persisted `process_id` remains zero

### Requirement: Version-agnostic parent allowlist matching

The `suspicious_exec` rule's non-shell parent allowlist (configured by `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST`) SHALL match an allowlist entry against the candidate parent process path treating the `*` character as a wildcard that matches any run of characters including the path separator. An entry that contains no `*` MUST match only by exact string equality, preserving the behavior of existing literal-path configurations. As today, a candidate whose non-shell parent matches an allowlist entry is suppressed for both arms of the rule, and a finding with no resolved non-shell parent is never suppressed by the allowlist.

#### Scenario: A glob allowlist entry suppresses a version-stamped parent

- **GIVEN** a `suspicious_exec` configuration whose parent allowlist contains the entry `*/claude/versions/*`
- **AND** a chain whose non-shell parent path is `/Users/dev/.local/share/claude/versions/2.1.178/claude` spawns a shell that makes an outbound connection to a public address
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding, because the version-stamped parent path matches the glob entry

#### Scenario: A literal allowlist entry still matches exactly

- **GIVEN** a `suspicious_exec` configuration whose parent allowlist contains the literal entry `/usr/libexec/sshd-session`
- **AND** an otherwise-identical chain whose non-shell parent path is `/usr/libexec/sshd-session`
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding, because the literal entry matches the parent path exactly

### Requirement: Local-resolver DNS suppression for the network arm

The `suspicious_exec` rule MUST NOT treat an outbound `network_connect` event to remote port 53 as a triggering outbound connection when the event's `remote_address` parses as a local-resolver-class IP address: an IPv4 or IPv6 loopback address, an RFC1918 private address, an IPv4 link-local address, an address in the CGNAT range `100.64.0.0/10`, an IPv6 unique-local address, or an IPv6 link-local address. An outbound connection to port 53 whose `remote_address` is any other (publicly routable) address MUST still be eligible to trigger the network arm. This suppression applies only to the outbound-network arm; it does not affect the temp-path-exec arm.

#### Scenario: Outbound DNS to a local resolver does not count as a network connection

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `100.100.100.100` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding from the network arm, because the destination is the host's local-resolver-class address on the DNS port

#### Scenario: Outbound DNS to a public resolver still fires

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `8.8.8.8` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces a `suspicious_exec` finding from the network arm, because the destination is a publicly routable address
