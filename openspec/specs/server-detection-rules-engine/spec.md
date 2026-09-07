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

The system SHALL register the following named rules at startup so each becomes evaluable against every batch of its target platform: `suspicious_exec`, `shell_network_connect`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, `sensor_tamper`, `application_control_block`, and `sensor_recovery_failed`. The registered-rule metadata SHALL report each rule's target platforms.

The operator-facing catalog SHALL report the registered rules that are detections. Registration and evaluation are unchanged for the rest: a registered rule that is not a detection is still evaluated against every batch of its target platform and still persists its findings as alerts.

The changes from the prior requirement are the addition of `sensor_tamper` and `sensor_recovery_failed`, the first two rules whose subject is the EDR itself rather than the host it watches; the addition of `shell_network_connect`, the outbound-connection shape separated from `suspicious_exec` so each can be tuned and promoted on its own; the addition of `application_control_block`, which was registered and evaluated all along but was never named here; and that the operator-facing catalog now reports the registered rules that are detections rather than every registered rule. Naming `application_control_block` matters because of that last change: while registration and the catalog were the same thing, leaving it out was harmless, and now it would let the spec permit dropping its alerts entirely.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_network_connect`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, and `sensor_tamper`

#### Scenario: Rule metadata reports target platforms

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the registered-rule metadata
- **THEN** each rule reports the operating-system platforms it targets

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

The system SHALL stamp each persisted alert with MITRE ATT&CK technique identifiers, taken from the finding first and the rule second. A finding that states a list of its own is stamped with that list, which is how a rule covering several techniques claims only the ones that applied to the finding at hand rather than its whole union. A finding that states none inherits the list its rule declares. A technique carried by a conditional escalation that applied is added to whichever of those was used, and a technique already present is not repeated.

The stamped list MUST be preserved on the alert row even if the rule's technique mapping is later refined.

A rule SHALL declare a technique only for something it OBSERVED, not for the subject it is about.

What counts as observing it depends on what the technique NAMES, and the two cases are different obligations. A technique that names a BEHAVIOUR is observed when the behaviour is: a Unix shell ran whether an administrator or an intruder started it, so a rule that matches the shell has seen the technique and does not owe an account of intent. A technique that names an ACTOR'S ACTION is observed only when something about the actor is: impairing defenses is somebody doing something, and a rule that sees only the resulting state has not seen it, however reliably that state follows from the action.

A rule that cannot observe what its technique names SHALL declare none.

Separating a known benign explanation from what a rule reports is what makes the rule's signal sound, and it is a different question from which technique the rule may declare. A rule that names a product-caused false positive and then discriminates against it still has to meet the test above for whatever it declares: the separation earns the alert, not the attribution. And a rule whose own documentation names this product's components among the likely causes of the very thing it reports has separated nothing. It is describing a state with several possible causes, one of them ours, which is neither an observed behaviour nor an observed actor.

Declaring none is a complete mapping rather than a gap. A signal that a host has stopped capturing is an operational statement, and it earns its severity from the consequence rather than from an attribution: a host that is not capturing needs an operator whatever caused it. An unearned technique is not a harmless overstatement either, because it reaches the alert row an analyst reads and, for a rule that appears on the operator-facing catalog, the coverage export a customer reads.

A rule that declares no technique SHALL NOT itself write one into its alert text either. The text is carried onto the alert verbatim and read by the same analyst, so an attribution the rule puts in prose is the same claim by another route, and removing it from the structured mapping alone leaves the claim standing where it is actually read. Text an operator supplied is theirs to write and is out of scope: a rule that passes it through is not the one making the claim.

Where a rule matches something specific enough to identify a sub-technique, it SHALL declare the sub-technique rather than its parent, and SHALL NOT declare both. A rule that matches a shell by path knows which interpreter ran, so the parent understates a claim that is actually precise, and a coverage export renders a parent hit differently from a sub-technique one. Declaring both is the same overstatement twice.

#### Scenario: A rule advertises ATT&CK techniques

- **GIVEN** a rule that declares technique identifiers such as `T1059.002` and `T1105`
- **WHEN** the rule fires and an alert is persisted
- **THEN** the alert row carries those technique identifiers
- **AND** subsequent edits to the rule's technique mapping do not modify the historical alert's stamped list

#### Scenario: A rule that cannot attribute what it reports declares no technique

- **GIVEN** a rule reporting that the agent's own recovery of a stopped capture provider gave up
- **AND** that rule documents this product's own components among the likely causes
- **WHEN** it fires and an alert is persisted
- **THEN** the alert row carries no ATT&CK technique
- **AND** its text names none either
- **AND** the alert keeps its severity and its operational explanation, because the host still needs an operator

#### Scenario: A rule declares the sub-technique it can identify

- **GIVEN** a rule whose match identifies a sub-technique, such as one matching a Unix shell by path
- **WHEN** its ATT&CK mapping is read
- **THEN** it names that sub-technique
- **AND** it does not also name the parent technique

### Requirement: Rule failure isolation, batch retry on persistence failure

The system SHALL isolate a single rule's evaluation failure so that other rules in the batch still run, EXCEPT where the failure means the rule's dependency was unavailable rather than that the rule was wrong: a failed READ of the process graph SHALL fail the batch with the retryable error class, so the processor re-evaluates those events rather than acknowledging them. The system MUST NOT silently drop alerts on persistence failures: when persisting a finding fails, the batch is surfaced as failed so the processor can retry it.

Isolation and retry are the right handling of two different conditions, and treating them alike loses detections silently. A BROKEN rule must be isolated: retrying cannot change its answer, and failing the batch on it would let one defective rule stop detection for every other rule. A rule whose graph read FAILED is not broken. The answer is merely unavailable, the events are still in the work queue, and every rule in that batch that reads the graph is equally affected, so isolating one of them and acknowledging the batch discards the evaluation of all of them.

A graph read failure SHALL fail the batch regardless of which rule performed the read, and no rule SHALL be required to classify the failure itself for this to hold. A contract that depends on each rule remembering to mark its own read failures retryable is one an added rule silently breaks, and the resulting loss is invisible.

A failed read SHALL be distinguished from a read that legitimately finds nothing. An absent row is an answer, and rules already handle it; only the failure to obtain an answer is retryable.

The retry this creates SHALL be bounded by the work queue's own bound rather than left open-ended, so that a read which fails permanently (as opposed to transiently) cannot hold its host's queue forever. The "A batch that cannot be processed does not stall its host" requirement of the server-event-ingestion capability is what supplies that bound.

#### Scenario: One rule errors during evaluation

- **GIVEN** a batch where one registered rule's evaluation returns an error unrelated to reading the process graph
- **WHEN** the engine processes the batch
- **THEN** the error is recorded and the engine continues evaluating the remaining rules
- **AND** the remaining rules' findings are persisted normally

#### Scenario: A failed process-graph read retries the batch instead of acknowledging it

- **GIVEN** a batch being evaluated while a read of the process graph fails
- **WHEN** a rule performs that read
- **THEN** evaluation fails with the retryable error class
- **AND** the processor does not acknowledge the batch, so the events are re-evaluated on a later cycle
- **AND** the events are not lost to a warning log

#### Scenario: A read that finds nothing is not a failure

- **GIVEN** a batch being evaluated while the process graph is healthy
- **WHEN** a rule's read matches no row
- **THEN** the absence is returned to the rule as an answer rather than as a retryable failure
- **AND** the batch is acknowledged normally

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

The system SHALL allow an operator to set an individual rule's mode to one of `alert`, `monitor`, or `disabled` through the durable detection-configuration surface (persisted in MySQL, edited via the admin API/UI), NOT through boot-time environment configuration. The mode MAY be set at global scope or scoped to a host group, and resolves per host most-specific-wins (a host-group setting overrides the global setting for hosts in that group). A rule that resolves to `disabled` for a host MUST NOT produce alerts for that host. A rule that resolves to `monitor` for a host MUST evaluate but MUST NOT persist an alert, emitting an observability signal instead so the would-be detection is visible without alerting. A rule that resolves to `alert` produces alerts as normal. A mode change MUST take effect without a server restart.

A rule whose global mode is `disabled` MUST remain visible in the rule catalog surface (`GET /api/rules`) with its mode indicated rather than being removed from the catalog. The mode indicated SHALL be the mode the rule RUNS IN at global scope: the globally scoped setting when one applies, and the rule's own declared default otherwise. The catalog SHALL also report which of those two produced it. A rule's declaration and the mode in force are different facts and a reader needs both: without the source, a rule sitting in `monitor` because that is how it shipped cannot be told from one an operator moved there, and those call for opposite follow-ups.

The mode and its source SHALL be resolved together, from one read of the configuration, so a listing cannot report a mode taken from one configuration version with a source taken from another. A stored setting whose mode the server cannot interpret SHALL report source `default`, because the default is what the server falls back to and therefore where the reported mode came from.

Global scope is what a catalog listing can answer, since the listing names no host. A per-host mode remains a separate resolution the engine performs at evaluation time.

An operator MAY also set a rule's severity, and that setting SHALL adjust what the rule decided rather than replace it. Where a rule raises a finding's severity because of a condition it observed, that escalation SHALL still apply on top of the severity the operator set, so an escalated finding continues to rank above an ordinary one from the same rule at every setting that leaves room above it. At the top of the scale there is no room, so the two rank equally there; that is the one setting at which an operator has said every finding from this rule is already as severe as the system can express.

Replacing is not a smaller version of adjusting, it is the opposite outcome. A rule that escalates conditionally reported one finished severity, and the setting overwrote it, so an operator who found the rule noisy and lowered it got the same answer for the escalated findings and the ordinary ones. The population they would most want to keep visible became indistinguishable from the rest, silently, as a result of an action taken to reduce volume.

An escalation SHALL therefore be expressed as an amount of risk it ADDS, not as a severity it arrives at. A destination is the same value however the rule was tuned, which reintroduces the same failure from the other side: the escalated findings would snap back to the rule's own opinion and ignore the operator's. Risk SHALL be bounded, so a stack of escalations on an already-severe finding stays within the scale rather than running off it. Composition SHALL be an identity where a finding carries no escalation, so a severity this system does not recognise passes through as it arrived rather than being reclassified into one that it does.

Where an escalation implies a MITRE technique, the technique SHALL be declared together with the risk it adds, and stamped on the finding by the same step that applies the risk. A rule cannot then grow a technique for a condition without saying what that condition is worth, and an operator retuning the amount is knowingly re-weighting that technique for their environment rather than creating an inconsistency. A technique the rule already declares SHALL NOT be duplicated by this, since a repeated technique inflates the coverage figure read during procurement.

#### Scenario: An operator disables a noisy rule for their environment

- **GIVEN** a running engine and an operator who sets a rule's global mode to `disabled` through the detection-configuration API
- **WHEN** a batch arrives that would otherwise satisfy that rule
- **THEN** no alerts are produced for that rule
- **AND** the remaining rules continue to evaluate normally
- **AND** the disabled rule is still listed by `GET /api/rules`, marked disabled
- **AND** the change took effect without a server restart

#### Scenario: The catalog reports the mode a rule runs in, not only the one it declares

- **GIVEN** a rule that declares `monitor` as its default and an operator setting that sets its global mode to `disabled`
- **WHEN** the rule catalog is listed
- **THEN** the entry reports mode `disabled` and source `setting`
- **AND** it still reports the rule's declared default of `monitor` alongside
- **AND** a rule with no setting reports its declared default with source `default`

#### Scenario: A rule set to monitor evaluates without alerting

- **GIVEN** a rule whose global mode is set to `monitor`
- **WHEN** a batch arrives that satisfies the rule for a host
- **THEN** no alert is persisted for that rule and host
- **AND** an observability signal records that the rule matched

#### Scenario: An operator re-enables a previously disabled rule

- **GIVEN** a rule whose global mode was previously set to `disabled`
- **WHEN** the operator sets its mode back to `alert` through the API
- **THEN** subsequent batches that satisfy the rule produce alerts again without a server restart

#### Scenario: A severity override adjusts an escalation rather than erasing it

- **GIVEN** a rule that raises a finding's severity when it observes some condition
- **AND** an operator who has set that rule's severity lower
- **WHEN** the rule produces one finding that met the condition and one that did not
- **THEN** both are ranked below where they would have been without the setting
- **AND** the one that met the condition still ranks above the one that did not
- **AND** with no setting in force, both carry exactly the severities they always did
- **AND** a finding carrying no escalation keeps the severity it arrived with, whatever that is

#### Scenario: An escalation's technique is stamped with its risk

- **GIVEN** a rule whose escalation implies a MITRE technique
- **WHEN** a finding meets that condition
- **THEN** the persisted alert carries that technique alongside the ones the rule declares
- **AND** a technique the rule already declares appears once

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

The system SHALL persist detection-rule configuration (per-rule mode, optional severity override, per-rule settings, and false-positive exclusions) as durable state in MySQL, edited through the authenticated admin API and UI. Detection configuration MUST NOT be sourced from boot-time environment variables. Every mutation MUST pass through the RBAC authorization chokepoint and record an audit entry naming the acting principal (a human user or a service account) by its principal id and a resolvable label. The per-row attribution column (`created_by` / `updated_by`) SHALL store the acting principal id; a service-account write MUST NOT be rejected at the persistence layer for lacking a human user id, and a system-originated write SHALL record the system principal (principal id `sys`, type `system`). Each configuration record MAY carry a host-group scope (or be global); records also support an optional expiration after which they no longer apply. A configuration change MUST become effective for subsequent evaluations without a server restart.

Each registered rule SHALL declare the set of exclusion match types it consults at evaluation time, and the rule catalog surface (`GET /api/rules`) SHALL expose that set for every rule so operator tooling can offer only the match types a rule actually reads. Creating an exclusion SHALL be rejected when its `rule_id` does not name a registered rule, and when its `match_type` is not one the named rule consults; the rejection is a client error that names the supported match types. This prevents an operator from storing an exclusion whose `(rule_id, match_type)` pair no rule reads, which would otherwise be accepted and displayed as active while suppressing nothing.

#### Scenario: An operator adds a false-positive exclusion without restarting

- **GIVEN** a rule that is currently producing a benign finding for a known-good process
- **WHEN** an operator adds an exclusion for that rule (by a typed match such as a parent-path glob or a signing team ID) through the detection-configuration API
- **THEN** the exclusion is persisted in MySQL with the acting principal id recorded in both the attribution column and the audit log
- **AND** subsequent batches no longer produce that finding, without a server restart

#### Scenario: A service account adds an exclusion and is attributed

- **GIVEN** an admin-roled service account holding the detection-config write permission
- **WHEN** it creates an exclusion through the detection-configuration API
- **THEN** the write succeeds without an `actor is required` rejection
- **AND** the exclusion's attribution column and the audit row both record the service account's principal id

#### Scenario: An expired exclusion stops applying

- **GIVEN** an exclusion whose expiration timestamp is in the past
- **WHEN** the engine evaluates a batch that the exclusion would otherwise suppress
- **THEN** the exclusion does not apply and the finding is produced

#### Scenario: The rule catalog exposes per-rule supported exclusion match types

- **GIVEN** the registered rule catalog
- **WHEN** a client reads `GET /api/rules`
- **THEN** each rule carries the set of exclusion match types it consults, as an array (empty for a rule that consults no exclusions)

#### Scenario: Creating an exclusion for a match type the rule does not consult is rejected

- **GIVEN** a rule that consults a fixed set of exclusion match types
- **WHEN** an operator attempts to create an exclusion for that rule with a match type outside the rule's supported set
- **THEN** the request is rejected as a client error whose message names the rule's supported match types
- **AND** no exclusion is persisted

#### Scenario: Creating an exclusion for an unknown rule is rejected

- **GIVEN** a `rule_id` that names no registered rule (including the empty string)
- **WHEN** an operator attempts to create an exclusion for it
- **THEN** the request is rejected as a client error and no exclusion is persisted

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

### Requirement: Version-agnostic parent allowlist matching

A rule's non-shell parent exclusions SHALL match an entry against the candidate parent process path treating the `*` character as a wildcard that matches any run of characters including the path separator. An entry that contains no `*` MUST match only by exact string equality, preserving the behavior of existing literal-path configurations. A candidate whose non-shell parent matches an entry is suppressed for the rule that entry names. A finding whose parent cannot be named is never suppressed by an entry, and NO finding lacking a resolved parent process record is ever suppressed by a code-signing exclusion, because there is no signing identity to match against. A shell started directly by process 1 is the exception to the first of those: process 1 is nameable, so an entry naming its path does match, which is what makes that class suppressible at all. Entries are per rule: the temp-exec and outbound-connect shapes are separate rules, so an entry saved against one does not suppress the other. The entries are the durable per-rule exclusions on the detection-configuration surface; the `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` environment variable this requirement previously named no longer exists.

#### Scenario: A glob allowlist entry suppresses a version-stamped parent

- **GIVEN** a `shell_network_connect` exclusion set containing the entry `*/claude/versions/*`
- **AND** a chain whose non-shell parent path is `/Users/dev/.local/share/claude/versions/2.1.178/claude` spawns a shell that makes an outbound connection to a public address
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `shell_network_connect` finding, because the version-stamped parent path matches the glob entry

#### Scenario: A literal allowlist entry still matches exactly

- **GIVEN** a `shell_network_connect` exclusion set containing the literal entry `/usr/libexec/sshd-session`
- **AND** an otherwise-identical chain whose non-shell parent path is `/usr/libexec/sshd-session`
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `shell_network_connect` finding, because the literal entry matches the parent path exactly

### Requirement: Local-resolver DNS suppression for the network arm

The `shell_network_connect` rule MUST NOT treat an outbound `network_connect` event to remote port 53 as a triggering outbound connection when the event's `remote_address` parses as a local-resolver-class IP address: an IPv4 or IPv6 loopback address, an RFC1918 private address, an IPv4 link-local address, an address in the CGNAT range `100.64.0.0/10`, an IPv6 unique-local address, or an IPv6 link-local address. An outbound connection to port 53 whose `remote_address` is any other (publicly routable) address MUST still be eligible to trigger the rule. The suppression is scoped to this rule; `suspicious_exec` is unaffected.

#### Scenario: Outbound DNS to a local resolver does not count as a network connection

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `100.100.100.100` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `shell_network_connect` finding, because the destination is the host's local-resolver-class address on the DNS port

#### Scenario: Outbound DNS to a public resolver still fires

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `8.8.8.8` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces a `shell_network_connect` finding, because the destination is a publicly routable address

### Requirement: Canonical rule naming

The system SHALL give every detection rule one canonical human-readable name, distinct from its stable snake_case identifier, and reuse that one name across every operator-facing surface. The rule's documentation title (surfaced in `/api/rules` and `docs/detection-rules.md`) and the title of every alert the rule raises SHALL both be that canonical name, so an operator who triages an alert, reads the documentation, and writes an exclusion sees one name mapped to one rule. A rule that fires on more than one trigger arm SHALL still raise its findings under the single canonical name; the distinguishing arm detail belongs in the finding's description, not in a divergent title. The rule identifier SHALL remain unchanged by this requirement.

The application-control block rule is exempt from the alert-title half: its alerts carry a per-block computed title that names the blocked binary and a per-rule identifier (`app_control:<n>`) rather than the catalog rule's identifier, because those alerts name the admin rule and binary that were blocked rather than a catalog detection. Its documentation title SHALL still be the canonical name.

#### Scenario: A rule names itself the same way everywhere

- **GIVEN** any registered catalog rule other than the application-control block rule
- **WHEN** the rule's documentation title is read and the rule fires to raise an alert
- **THEN** the documentation title equals the rule's canonical name
- **AND** the alert's title equals that same canonical name
- **AND** the canonical name is a clean human-readable label carrying no parenthetical implementation detail

#### Scenario: A multi-arm rule raises one canonical title across arms

- **GIVEN** the `suspicious_exec` rule, which fires on either a temp-path exec arm or an outbound network-connection arm
- **WHEN** either arm fires
- **THEN** the alert title is the one canonical name "Suspicious exec chain"
- **AND** the finding description names which arm fired

### Requirement: Alert evidence is self-contained

When the system persists an alert, it SHALL capture the payloads of the alert's triggering events into durable, alert-scoped storage, in addition to recording their `event_id` values (the "Alert-to-event linkage" requirement). An alert's evidence SHALL remain resolvable independently of the event archive's retention window, so opening an alert returns its triggering-event payloads even after those events have aged out of the event archive. This keeps alert evidence self-contained and removes any dependency of archive retention on a cross-store reference.

#### Scenario: Triggering-event payloads are captured at alert creation

- **GIVEN** an event batch that satisfies one rule's pattern
- **WHEN** the engine persists the resulting alert
- **THEN** the payloads of the alert's triggering events are stored as alert-scoped evidence
- **AND** the alert still records the `event_id` values of those triggering events

#### Scenario: Evidence survives event-archive expiry

- **GIVEN** a persisted alert whose triggering events have since aged out of the event archive
- **WHEN** an operator requests the alert detail
- **THEN** the alert's captured triggering-event payloads are still returned as its evidence

### Requirement: Platform-scoped rule evaluation

Every registered rule SHALL declare one or more target platforms, each one of `darwin`, `windows`, or `linux`. The detection engine SHALL evaluate a rule only against the events whose platform is in that rule's declared set, so a rule targeting one platform never fires on another platform's events. An event carrying no platform SHALL be treated as `darwin`, the default for an agent predating the platform-aware contract. A rule with no matching events in a batch SHALL be skipped.

#### Scenario: A darwin-only rule does not see windows events

- **GIVEN** a rule that declares only darwin and a batch containing a windows event
- **WHEN** the engine evaluates the rule
- **THEN** the windows event is not passed to the rule

#### Scenario: A mixed-platform batch is filtered per rule

- **GIVEN** a darwin-only rule and a windows-only rule evaluating a batch that contains a darwin event and a windows event
- **WHEN** the engine evaluates both rules
- **THEN** the darwin rule sees only the darwin event and the windows rule sees only the windows event

#### Scenario: An event without a platform is evaluated as darwin

- **GIVEN** a darwin-only rule and an event that carries no platform
- **WHEN** the engine evaluates the rule
- **THEN** the platform-less event is passed to the rule

#### Scenario: Every cataloged rule declares at least one valid platform

- **GIVEN** the registered rule catalog
- **WHEN** each rule's declared platforms are inspected
- **THEN** every rule declares a non-empty set and every declared platform is a recognized value

### Requirement: Signature-based parent exclusions

The `suspicious_exec` rule SHALL suppress a finding when the chain's non-shell parent process matches an operator exclusion by its code-signing identity, in addition to the existing parent-path-glob match. The consulted signature dimensions are the parent's Apple Developer team ID (`team_id`), its code-signing identifier (`signing_id`), and its code-directory hash (`cdhash`), read from the parent process's already-persisted code-signing record; no agent or event-wire change is required. A finding with no resolved non-shell parent, or a parent that carries no signing identity, MUST NOT be suppressed by a signature exclusion, so an unsigned binary at a benign-looking path is not silently allowed. This lets an operator exclude a code-signed developer tool by its non-spoofable signing identity instead of a path glob that an attacker who can write to a world-writable directory could land inside.

#### Scenario: A signed parent is suppressed by its team ID

- **GIVEN** a `suspicious_exec` chain whose non-shell parent is a code-signed binary with team ID `Q6L2SF6YDW`
- **AND** an exclusion of match type `team_id` with value `Q6L2SF6YDW` for `suspicious_exec`
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding, because the parent's signing team ID matches the exclusion
- **AND** the same holds for a `signing_id` exclusion matching the parent's signing identifier and a `cdhash` exclusion matching the parent's code-directory hash

#### Scenario: An unsigned lookalike parent is not suppressed

- **GIVEN** an exclusion of match type `team_id` with value `Q6L2SF6YDW` for `suspicious_exec`
- **AND** a `suspicious_exec` chain whose non-shell parent is an unsigned binary at a path resembling the benign tool (for example `/tmp/claude/versions/1.0/claude`)
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the finding is produced, because the unsigned parent carries no team ID for the signature exclusion to match

### Requirement: Retryable evaluation on unmaterialized flow process

The system MUST NOT silently drop a `dns_c2_beacon` alert because the rule evaluated a `network_connect` before a concurrently processed batch committed the connecting process's row (intra-replica processor workers and cross-replica claimers both create this window). When the rule resolves the flow's process and the lookup misses while the connect's ingest age is inside a fixed flow-materialization grace window, evaluation SHALL fail the batch with the retryable not-yet-materialized error class so the processor does not acknowledge the events and re-evaluates them on a later cycle, by which time the concurrent flush has committed. Once the connect is older than the grace window, a missing flow process SHALL be treated as permanently absent (its exec was never delivered) and the connect evaluated without a finding, so an orphaned connect cannot hold its batch in a retry loop.

This flow-process grace window MUST be materially tighter than the subject-process materialization grace, because flow resolution runs before the rule's suspicion gate and so is reachable by any outbound connect rather than only a pre-filtered event; the tighter bound caps the batch-retry cost a genuinely orphaned connect can incur under sustained load while still covering the ordering race, which commits within a batch flush.

A connect whose flow process is permanently absent MUST NOT prevent the rule from evaluating the remaining events in the same batch. Rule evaluation SHALL continue past a flow-materialization miss and report it only after every event in the batch has been evaluated, returning the findings that did resolve alongside the miss. Returning on the first miss let an orphaned connect (whose row never arrives, so it misses on every retry) hold the rule at that event for the whole of its own grace window; a resolvable beacon later in the same batch was then first evaluated only after its own, tighter grace had already elapsed, at which point a still-uncommitted row degraded to the silent skip and the alert was lost permanently.

#### Scenario: A young outbound connect's flow process row is missing

- **GIVEN** an outbound `network_connect` whose connecting process has no materialized process row
- **AND** the connect was ingested more recently than the flow-materialization grace window
- **WHEN** the `dns_c2_beacon` rule evaluates it
- **THEN** evaluation fails with the retryable not-yet-materialized error class
- **AND** the processor does not acknowledge the batch, so the events are re-evaluated on a later cycle
- **AND** the alert is produced by the re-evaluation once the process row is committed

#### Scenario: An outbound connect past the grace window has no flow process row

- **GIVEN** an outbound `network_connect` whose connecting process has no materialized process row
- **AND** the connect was ingested longer ago than the flow-materialization grace window
- **WHEN** the `dns_c2_beacon` rule evaluates it
- **THEN** the connect produces no finding and no error
- **AND** the batch is acknowledged normally

#### Scenario: An unresolvable event does not mask resolvable findings in the same batch

- **GIVEN** a batch containing an outbound `network_connect` whose connecting process row never materializes
- **AND** the same batch contains a later outbound `network_connect` from a temp-path process that resolved the address it is connecting to
- **WHEN** the `dns_c2_beacon` rule evaluates the batch
- **THEN** the finding for the resolvable connect is produced
- **AND** the unresolvable connect's retryable not-yet-materialized error class is still reported so the batch is re-evaluated

### Requirement: Retryable evaluation on unmaterialized subject process

The system MUST NOT silently drop an alert because rule evaluation ran before a concurrently processed batch committed the event's subject process row (intra-replica processor workers and cross-replica claimers both create this window). When a rule resolves the process an event is about (the pid carried in the event's own payload) and the lookup misses while the event's ingest age is inside a fixed materialization grace window, evaluation SHALL fail the batch with a retryable error class so the processor does not acknowledge the events and re-evaluates them on a later cycle. Once an event is older than the grace window, a missing subject process SHALL be treated as permanently absent and the event evaluated without a finding, so an orphaned event cannot hold its batch in a retry loop. This subject-process retry contract applies to subject-process lookups; ancestor and parent-chain lookups keep the skip semantics. (`dns_c2_beacon`'s flow-to-process resolution, which runs before its suspicion gate, uses an analogous retry under a tighter grace, specified separately by the "Retryable evaluation on unmaterialized flow process" requirement.)

A retryable miss MUST NOT reduce the evaluation any other rule or event receives from the same batch. Specifically: every registered rule SHALL be evaluated against the batch even after an earlier rule reported a miss, and the findings a rule did resolve SHALL be persisted even when that same rule also reported one. The miss SHALL be reported after every rule has run, so the processor still declines to acknowledge the batch. Stopping at the first miss meant a rule waiting on a row that never arrives suppressed every rule registered after it for the whole of its own grace window, and because the grace windows differ per rule, the suppressed rules were first evaluated only after their own (shorter) windows had elapsed, converting a recoverable race into permanent alert loss.

Non-retryable failures keep their existing semantics: an ordinary rule-evaluation error is logged and swallowed so one misbehaving rule cannot wedge the pipeline, and an alert-persistence error aborts the batch immediately.

#### Scenario: A young event's subject process row is missing

- **GIVEN** an event whose payload references a pid with no materialized process row
- **AND** the event was ingested more recently than the materialization grace window
- **WHEN** a rule that resolves that event's subject process evaluates it
- **THEN** evaluation fails with the retryable not-yet-materialized error class
- **AND** the processor does not acknowledge the batch, so the events are re-evaluated on a later cycle
- **AND** the alert is produced by the re-evaluation once the process row is committed

#### Scenario: An event past the grace window has no subject process row

- **GIVEN** an event whose payload references a pid with no materialized process row
- **AND** the event was ingested longer ago than the materialization grace window
- **WHEN** a rule that resolves that event's subject process evaluates it
- **THEN** the event produces no finding and no error
- **AND** the batch is acknowledged normally

#### Scenario: A retryable miss does not suppress the remaining rules

- **GIVEN** a batch that a rule reports a retryable not-yet-materialized error class for
- **AND** another rule is registered after it
- **WHEN** the engine evaluates the batch
- **THEN** the rule registered after the miss is still evaluated against the batch
- **AND** the retryable error class is still reported so the processor does not acknowledge the batch

#### Scenario: Findings resolved in a batch persist alongside a retryable miss

- **GIVEN** a rule that resolves a finding for one event in a batch and reports a retryable not-yet-materialized error class for another
- **WHEN** the engine evaluates the batch
- **THEN** an alert is persisted for the resolved finding
- **AND** the retryable error class is still reported so the processor does not acknowledge the batch
- **AND** re-evaluation of the batch does not create a duplicate alert for the already-persisted finding

### Requirement: EDR sensor recovery failure detection

A stopped capture provider that the agent cannot restore leaves the host not reporting that telemetry until a person intervenes, and the existing stop finding cannot say so: it is raised seconds after the stop, when the outcome is not yet known, and it therefore reads identically for a host that repaired itself and one that did not. The system SHALL register a `sensor_recovery_failed` rule that raises a finding when the agent reports that its automatic repair of a capture provider has exhausted its attempts.

The finding SHALL carry no ATT&CK technique, and its text SHALL name none either. The rule's own documentation sends an analyst to this product's components as the likely cause of what it reports, so there is no actor for it to attribute. Stated here as well as in the change that decided it, because a requirement mandating the technique would archive alongside the one forbidding it.

The finding SHALL carry a higher severity than the stop finding that precedes it, because a stop may already have been repaired by the time an analyst looks whereas this state persists until someone acts.

The finding SHALL name the provider to restore and SHALL report how many repair attempts were made, so it is distinguishable from a repair that was never attempted.

The finding SHALL report which failure shape was reached, because they implicate different parts of the host: the repair command failing points at the host application or the configuration daemon, while every repair reporting success and the provider staying stopped means re-enabling is not what the fault needs. An outcome the server does not recognise SHALL still produce a finding, described in general terms rather than dropped, so that a newer agent reporting a new shape is not silently unreported.

The rule SHALL NOT wait or re-evaluate before deciding. Unlike the stop finding, whose meaning depends on what happens next, its input reports a settled outcome.

Repeated evaluation of one exhaustion SHALL collapse to a single alert, while a separate exhaustion SHALL raise its own.

A provider an operator has deliberately disabled SHALL NOT produce a finding. The agent does not attempt to repair a provider reported as a supported opt-out, so no record exists for it to evaluate.

#### Scenario: Automatic recovery gives up and raises a finding

- **GIVEN** a host whose capture provider stopped
- **WHEN** the agent reports that its repair attempts for that provider are exhausted
- **THEN** the engine produces one `sensor_recovery_failed` finding
- **AND** that finding carries no ATT&CK technique
- **AND** the finding names the provider and reports how many repairs were attempted

#### Scenario: The finding outranks the stop it follows

- **GIVEN** a stop finding and a recovery-failure finding for the same provider on one host
- **WHEN** an operator compares them
- **THEN** the recovery-failure finding carries the higher severity

#### Scenario: A repair that succeeds raises nothing

- **GIVEN** a host whose capture provider stopped
- **WHEN** the agent restores that provider within its attempt budget
- **THEN** the engine produces no `sensor_recovery_failed` finding

#### Scenario: An unrecognised outcome is still reported

- **GIVEN** an exhaustion record whose reported failure shape this server does not recognise
- **WHEN** the engine evaluates it
- **THEN** the engine still produces a finding, described without asserting a specific failure shape

### Requirement: Alerts from vendored rules are credited

The system SHALL credit alerts that carry no attribution but were raised by a rule this project did not write, so the licence obligation those rules carry is met for alerts raised before attribution was recorded rather than only for later ones.

Two replicas SHALL NOT run the pass concurrently, and a replica SHALL NOT block startup on winning the right to run it.

The pass SHALL run at most once SUCCESSFULLY per deployment rather than once per start, which is a bound on completed work and not on attempts: an attempt that does not finish is retried, per the paragraph below. A leader lock alone does not give that: it excludes callers that OVERLAP and is released when the work returns, so replicas starting in sequence each acquire it in turn and each run the whole pass. The system SHALL therefore record durably that the pass completed, and a later start SHALL determine from that record that there is nothing to do without reading the alerts it would otherwise credit.

Recording completion SHALL follow a successful pass rather than accompany it. A pass that fails, or that a shutdown cuts short, SHALL record nothing and SHALL be retried on the next start: an unmet licence obligation that no later start will notice is worse than repeating work that is idempotent.

It SHALL touch only alerts whose attribution is absent, so an attribution already recorded is never overwritten and repeating the pass changes nothing.

Three classes of alert SHALL NOT be credited, and each is irreversible if credited wrongly:

- An alert raised by a rule this project wrote. The absence of attribution on those rows is meaningful: it distinguishes an alert raised before attribution existed from one raised by this project, and crediting them collapses the two.
- An alert raised by a projection of an operator's own configuration, whose rule identifier names the operator's policy entry rather than a detection. Crediting those claims authorship of the operator's configuration.
- An alert whose rule is now one the operator wrote themselves. A rule's identifier is its file stem, so an operator who writes their own version of a rule that shipped with the product keeps that identifier: the rule running now is theirs, while the historical alerts under that identifier were raised by the rule that shipped. Crediting those to the operator would state permanently that they wrote a detection they did not.

The pass SHALL bound how much it rewrites in a single statement. Alerts carry no index that this predicate can use, so an unbounded rewrite would hold row locks across a full scan at start-up, on a system that may already be serving.

Alerts from a rule the deployment no longer runs SHALL NOT be credited, and that limit is stated rather than worked around: crediting them would require a record of every rule that ever shipped, and guessing an author is worse than leaving the field empty. Tracked as #871, which #768's versioned rule packs would supply the provenance record for. Recording completion does not narrow that limit so much as fix its scope: a rule absent when the pass ran is not revisited if it returns later, and the same record of who wrote a rule that is no longer present is what would let a differently-scoped pass credit those rows.

A failure to credit SHALL NOT prevent the system from starting or from detecting, because an unpaid credit on historical rows is not a reason to stop detecting today, and the next start retries.

Crediting SHALL NOT delay the system becoming able to serve. Its cost scales with alert history rather than with anything bounded, nothing a request can observe depends on it, and a rolling restart would otherwise pay that cost once per replica before each could serve.

#### Scenario: An uncredited alert is credited

- **GIVEN** an alert raised by a rule this project did not write, carrying no attribution
- **WHEN** the pass runs
- **THEN** the alert is credited to that rule's author

#### Scenario: Our own rule is left alone

- **GIVEN** an alert raised by a rule this project wrote, carrying no attribution
- **WHEN** the pass runs
- **THEN** the alert still carries no attribution, because that absence distinguishes it from one raised before attribution existed

#### Scenario: A projection is left alone

- **GIVEN** an alert raised by a projection of an operator's own configuration, carrying no attribution
- **WHEN** the pass runs
- **THEN** the alert still carries no attribution, because its rule identifier names the operator's entry rather than a detection

#### Scenario: A rule the operator has since written themselves is left alone

- **GIVEN** an alert carrying no attribution, raised under an identifier whose rule is now content the operator wrote
- **WHEN** the pass runs
- **THEN** the alert still carries no attribution, because those alerts were raised by the rule that shipped under that identifier

#### Scenario: A recorded attribution is not overwritten

- **GIVEN** an alert already carrying an attribution
- **WHEN** the pass runs
- **THEN** that attribution is unchanged, and running the pass again changes nothing

#### Scenario: More alerts than one batch are all credited

- **GIVEN** more uncredited alerts from a vendored rule than the pass rewrites in a single statement
- **WHEN** the pass runs
- **THEN** every one of them is credited

#### Scenario: A start after a completed pass reads no alerts

- **GIVEN** a pass that has already completed on this deployment
- **WHEN** the system starts again, on this replica or another
- **THEN** it determines there is nothing to do from the recorded completion
- **AND** it does not read the alerts it would otherwise credit

#### Scenario: A pass that fails is retried

- **GIVEN** a pass that fails partway, or that a shutdown cuts short
- **WHEN** the system starts again
- **THEN** the pass runs again
- **AND** the alerts it had not reached are credited

### Requirement: Our events supply the Sigma fields a rule reads

The system SHALL map Sigma's field names onto our event payloads, so a rule written in the Sigma format can be evaluated against captured telemetry.

The system SHALL resolve a rule's logsource category to the event type whose payload supplies its fields, and SHALL decline a category for which it supplies no fields rather than accepting one it could name but not populate.

The system SHALL decode an event's payload once and reuse it for every rule evaluated against that event. Field access itself SHALL allocate nothing, because it runs for every field of every rule against every event.

The system SHALL report a field as absent when the payload does not carry it, so that a rule matching on absence behaves as its author intended.

The system SHALL supply a file-event rule's target filename only for an open that carries write intent. The Sigma category names file creation and modification rather than any access, and read-only opens of a watched path are routine background activity, so supplying them would present known noise to every such rule as a detection.

#### Scenario: Our events supply the Sigma fields a rule reads

- **GIVEN** a rule whose fields are all mapped for its event type
- **WHEN** an event of that type is evaluated
- **THEN** the rule sees the values its payload carries

#### Scenario: A read-only open supplies no target filename

- **GIVEN** a file-open event that opens a path for reading only
- **WHEN** a file-event rule is evaluated against it
- **THEN** the rule sees no target filename, and does not match

#### Scenario: A rule is inert against an event type it does not name

- **GIVEN** a rule whose logsource names one event type
- **WHEN** it is evaluated against an event of a different type
- **THEN** it does not match, rather than matching on a field that happens to share a name

### Requirement: A rule reading a field we do not supply is refused when it loads

The system SHALL refuse to load a rule that reads a field its event type does not supply, naming both the unsupplied fields and the fields that are available.

A rule naming a field we never populate would evaluate to false on that field for every event, for as long as it remained installed. That is indistinguishable from the adversary behaviour never occurring, so it is reported when the rule loads rather than discovered from an absence of alerts.

The system SHALL refuse a rule whose event type has no field mapping at all, distinctly from one whose fields are individually unavailable, so the reader can tell "we do not map this kind of event" from "we do not have this field".

#### Scenario: A rule reading a field we do not supply is refused

- **GIVEN** a rule reading a field its event type does not supply
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the field and the fields that are available

### Requirement: A rule's pattern cannot make matching arbitrarily expensive

The system SHALL refuse a rule whose patterns would cost more than a bounded amount to match, and SHALL refuse it when the rule loads rather than when it first evaluates.

What is bounded is the cost the AUTHOR imposes, which is not the whole cost of matching an event. Two event-side factors are deliberately outside it, and both were measured to be event-bounded rather than author-bounded. A field's authored values are each compared against every value the event supplies, and some event fields carry as many values as a process had arguments. Separately, comparing one value costs in proportion to the EVENT's string, not the author's: a literal or an end-anchored portion stops as soon as the event's string ends, so lengthening the authored side beyond it adds nothing. Bounding what an arbitrary event can provoke means measuring an evaluation rather than estimating a pattern, and belongs with the per-rule evaluation budget.

This requirement exists because a premise expired. The bound on wildcard matching was stated for attacker-supplied VALUES against a trusted pattern; once operators author rules, the pattern is untrusted input too, and the cost a pattern imposes is paid once per value, per field, per rule, for every event.

The bounds SHALL be placed where every pattern passes through on its way to being matched, so that the validation a publish runs and the loading a server does cannot disagree about what is acceptable. A rule accepted at publish and refused at load, or the reverse, is worse than either answer alone.

Cost SHALL be bounded both per pattern AND per field, summed across that field's values. Per-pattern bounds alone do not bound what an event pays: a field's values are tried until one matches, so an event matching none of them pays for every one, and a field of individually cheap patterns can cost far more than any single pattern the bound would refuse.

The estimate SHALL reflect what matching actually costs rather than what a pattern looks like. Two corrections are recorded because each was wrong first. A wildcard pattern's cost is the LENGTH of a segment with a star on either side, not the count of single-character wildcards in it: such a segment is searched for at every candidate offset, and a run of literal characters there costs the same order as a run of wildcards. A regular expression's cost is the size of the program it compiles to, not the length of its source: counted repetition expands at compile time, so a seven-character source can produce an enormous program.

Where a cost can be removed rather than refused, the system SHALL remove it. Adjacent wildcards that mean what one wildcard means SHALL be collapsed when the pattern is compiled, because refusing a pattern that means nothing unusual serves nobody.

A refusal SHALL name the field and the limit it exceeded, and SHALL say whether the limit was reached by one pattern or by the field's values together. An operator who has just written a rule needs to know which part to change.

Bounds SHALL be set from measurement against the matcher, and a bound that constrains nothing SHALL NOT be added. A limit nobody can trip is not free: it trains a reader to treat the limits as decorative, and invites a later change to raise it without measuring.

Every rule the system ships SHALL still load, and a rule refused for cost SHALL NOT prevent the rest of the content from loading.

#### Scenario: A pattern costing more than the limit is refused

- **GIVEN** a rule with a pattern whose unanchored portion is longer than the limit allows, whether it is written as wildcards or as literal characters
- **WHEN** the rule is loaded
- **THEN** it is refused, naming the field and the limit

#### Scenario: A pattern is not charged for a portion anchored to the ends of the value

- **GIVEN** a rule whose long pattern portion sits at the start or the end of the pattern rather than between two wildcards
- **WHEN** the rule is loaded
- **THEN** it is accepted however long that portion is, because such a portion is compared once rather than searched for at every offset
- **AND** it is still charged the base cost every value pays for being compared at all

#### Scenario: A pattern is not charged for a literal it compares whole

- **GIVEN** a rule whose pattern is a plain literal longer than any limit
- **WHEN** the rule is loaded
- **THEN** it is accepted, because comparing it stops as soon as the event's own string ends, so its length costs the author nothing
- **AND** it is still charged the base cost every value pays for being compared at all

#### Scenario: A field costing more than the limit across its values is refused

- **GIVEN** a rule whose single field lists values that are each within the per-pattern limit but together exceed the field limit
- **WHEN** the rule is loaded
- **THEN** it is refused, naming the field and saying the limit was reached across its values
- **AND** a field listing many values that each cost nothing to match is still accepted

#### Scenario: Adjacent wildcards are collapsed rather than refused

- **GIVEN** a pattern containing a run of adjacent wildcards
- **WHEN** it is compiled
- **THEN** it costs what the same pattern with one wildcard costs
- **AND** it matches exactly what that pattern matches

#### Scenario: A rule refused for cost does not stop the others loading

- **GIVEN** content in which one rule exceeds a cost limit and the others do not
- **WHEN** the content is loaded
- **THEN** the offending rule is refused by name, with a reason
- **AND** every other rule in that content loads

#### Scenario: The content the system ships is unaffected

- **GIVEN** the rule content compiled into the build
- **WHEN** it is loaded
- **THEN** every rule that loaded before these bounds existed still loads

### Requirement: A rule that repeatedly exceeds its evaluation budget stops being evaluated

The system SHALL bound how long one rule may take to evaluate one batch, and SHALL stop evaluating a rule that exceeds that bound repeatedly rather than continuing to pay it on every batch.

This exists because estimating a pattern's cost cannot bound the cost of an evaluation. Bounds on authored patterns are proxies, and they deliberately leave the event side unbounded: a field's values are compared against every value an event supplies, and comparing one costs in proportion to the event's own string. Measuring the evaluation is the only thing that bounds the product.

Exceeding the budget SHALL NOT be reported as a rule failure. A failing rule causes the batch to be replayed, so a slow rule reporting failure would be retried into the same slow rule on every attempt, which is the stalled-host condition the queue's retry bound exists to prevent, reached by a different route. An overrun SHALL be recorded, the findings the evaluation already produced SHALL be kept, and the batch SHALL continue.

A rule SHALL be skipped only after exceeding the budget repeatedly AND over a period, never on a single overrun. One slow evaluation is not evidence: a cold cache, an unusually large batch, or a host that has just enrolled each produce one, and a rule doing legitimate work has been measured taking two orders of magnitude longer than the mean without being unaffordable.

Skipping SHALL NOT change the rule's configured mode, or what the system reports that mode to be. A mode is what an operator asked for and a skip is what the system is doing to protect itself; reporting one as the other misrepresents the operator's intent and leaves unclear who may undo it.

The skip SHALL be local to the replica that measured it and SHALL NOT outlive the process. Each replica protects itself against the load it actually sees, and a heuristic that survives a restart keeps punishing a rule for a condition that may have passed.

Skipping SHALL be observable as a counter and as a log record naming the rule and what it measured. A rule that has stopped being evaluated raises no alerts, which is indistinguishable from a rule that matches nothing, so the condition has to be reported rather than inferred.

The budget SHALL be set from measured evaluation times rather than chosen, and SHALL leave room above the slowest rule doing legitimate work.

The budget SHALL measure only a rule's OWN work, excluding time it spent waiting on reads of the process graph. Those reads are synchronous, so charging them would disable rules for being slow when the datastore was slow, and would do it in proportion to how much of the graph each rule consults: a datastore slowdown would remove much of the catalog at once, worst first among the rules doing the most correlation, at exactly the moment detections matter most. What is left is what a rule author controls.

Waiting SHALL be attributed to the rule whose evaluation TRIGGERED the read, including when the read is performed on behalf of an earlier rule that resolved the same event lazily. Lookups shared across a batch are performed once, by whichever rule first needs the result, and that rule is the one that waits. Crediting the wait to the rule that merely arranged the sharing leaves the waiting rule charged in full for a datastore it does not control, which is the outcome excluding the wait exists to prevent.

#### Scenario: A rule over budget on one batch is still evaluated on the next

- **GIVEN** a rule whose evaluation exceeds the budget once
- **WHEN** the next batch is processed
- **THEN** the rule is evaluated again

#### Scenario: A rule repeatedly over budget stops being evaluated

- **GIVEN** a rule that exceeds the budget on many batches over a period
- **WHEN** the bounds are both exceeded
- **THEN** the rule is no longer evaluated on that replica
- **AND** a counter and a log record name the rule and what it measured

#### Scenario: An overrun does not cause the batch to be replayed

- **GIVEN** a rule whose evaluation exceeds the budget
- **WHEN** the batch finishes
- **THEN** the batch is not replayed on account of the overrun
- **AND** any findings that evaluation produced are kept

#### Scenario: A skipped rule reports its configured mode unchanged

- **GIVEN** a rule the system has stopped evaluating for exceeding its budget
- **WHEN** the rule catalog is read
- **THEN** it reports the mode the operator configured, not a disabled one

#### Scenario: The other rules are unaffected

- **GIVEN** one rule being skipped for exceeding its budget
- **WHEN** a batch is processed
- **THEN** every other rule is evaluated as usual

#### Scenario: A rule slowed only by the datastore is not skipped

- **GIVEN** a rule whose own work is well inside the budget but whose graph reads take longer than the budget
- **WHEN** it is evaluated repeatedly enough to exceed the overrun bound
- **THEN** it is still evaluated, because the waiting is not charged to it

#### Scenario: Waiting is charged to the rule that triggered the read

- **GIVEN** two rules over one batch, where the first arranges a shared lookup without resolving it and a later rule triggers the read
- **WHEN** both are evaluated repeatedly enough to exceed the overrun bound
- **THEN** neither is skipped, because the wait is excluded from the rule that actually waited rather than credited to the rule that arranged it

### Requirement: Matching does not backtrack across the star-separated segments of a pattern

The system SHALL compile a rule's wildcard pattern when the rule loads, and SHALL match it without re-scanning any part of the pattern against the value more than once per candidate position.

For a pattern fixed at load, the system SHALL check each of the pattern's star-separated segments against the value independently, and SHALL NOT retry an earlier segment because a later one failed. A value is attacker-supplied and a pattern is not, so a matcher that re-runs the whole pattern from a new offset lets a host choose how much work the server does per rule, per field, for every event it sends.

A literal run at either end of a pattern SHALL be checked once, against that end of the value, rather than at every offset.

This is a bound on re-scanning, not on the constant, and the difference is worth stating plainly. Verifying a candidate position still compares up to a segment's length, so a value dense in near-misses of one segment still costs more than a benign value of the same size. What it cannot do is compound: no failure sends the matcher back to re-run earlier segments, which is what made the previous implementation quadratic in the pattern as a whole.

Matching SHALL be unchanged by compilation. A pattern SHALL match exactly the values it matched before, because an optimisation that alters what a detection matches changes what fires, silently and without an error to notice.

#### Scenario: A literal run after a star is checked once, not at every offset

- **GIVEN** a pattern whose last element is a literal run following a star
- **WHEN** it is prepared for matching
- **THEN** that run is held as an anchor tested against the end of the value, rather than as something retried at each offset

#### Scenario: Compilation does not change what a pattern matches

- **GIVEN** any wildcard pattern and any value
- **WHEN** both the compiled matcher and the reference implementation are asked
- **THEN** they answer identically

### Requirement: Non-detections are excluded from the operator-facing catalog

A registered rule MAY declare that it is not a detection, and SHALL state which kind it is: a `projection` of a decision made elsewhere, or a `health` signal about the sensor itself. A rule that declares nothing SHALL be treated as a detection, so that the common case requires no declaration and cannot be omitted from the catalog by oversight.

The system SHALL omit non-detections from the operator-facing rule catalog, from the ATT&CK coverage export, and from the generated rule documentation. Those surfaces describe detections an operator reads, tunes, and reasons about; a rule with no detection logic offers a tuning surface that does not exist, and one that makes no adversary claim inflates a coverage figure that is read during procurement.

The system SHALL NOT change how a non-detection is registered, evaluated, or persisted. The exclusion is confined to the catalog surfaces, so a non-detection continues to raise the same alerts with the same identifiers and severities.

#### Scenario: The catalog omits a non-detection

- **GIVEN** a registered rule that declares itself a projection or a health signal
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** that rule is absent from the catalog
- **AND** it is absent from the ATT&CK coverage export

#### Scenario: A non-detection still evaluates and alerts

- **GIVEN** a registered rule that declares itself a projection or a health signal
- **WHEN** the engine evaluates a batch that satisfies it
- **THEN** the rule is evaluated and its finding is persisted as an alert unchanged

#### Scenario: A rule that declares nothing is a detection

- **GIVEN** a registered rule that makes no non-detection declaration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** that rule is present in the catalog

### Requirement: Argument position is available as a field

The system SHALL derive from an exec event's argument vector the positional facts a detection needs, and expose them as fields a rule can match, because the Sigma format represents a command line as a single string in which argument boundaries and positions are no longer recoverable.

The system SHALL expose the verb a tool will act on, being the first non-flag token after the invocation name. A rule matching this SHALL NOT fire merely because the token it names appears somewhere in the command line, since a tool acts on its first operand and ignores the rest.

The system SHALL expose the operands that follow that verb, so a rule can ask whether any later argument matches a pattern without conflating it with the verb itself.

The system SHALL expose the environment assignments made at exec time that are visible in the argument vector. Those are the assignments an `env` invocation performs, and ONLY those. A shell's `VAR=value cmd` form is not visible in an argument vector at all, because a shell applies it without passing it as an argument, so the system SHALL NOT report the first argument of a non-`env` invocation as an assignment; reporting it would advertise coverage no agent can supply. Within an `env` invocation an assignment is only an assignment in leading position: the same text as a later argument is an operand of the program, not an assignment performed before it. A substring match over the whole command line cannot make that distinction, which is why the position is recovered here rather than left to the rule.

For an invocation of `env`, the assignments SHALL be the run of `KEY=VALUE` tokens that follows env's own OPTIONS, ending at the first token that assigns nothing, which is the command env will run. An option ahead of the assignments SHALL NOT end the run: an option is not the command, and treating it as one hid every assignment written behind it.

The end of that run SHALL be decided by whether a token assigns at all, and NOT by whether the name it assigns is one a shell would accept. env applies any nonempty name, so a token such as `2+2=4` is an assignment env performs and the run continues past it; ending the run there would hide an injection written behind it. Only WELL-FORMED assignments SHALL be reported, so the narrower test governs the reported set and the wider one governs the boundary.

An assignment whose NAME is empty is the exception, and it ends more than the run: env cannot set it, exits before executing anything, and therefore applied none of the assignments around it. Such an invocation SHALL report no assignments at all. The discriminator is emptiness rather than shell-legality, which is why this does not reopen the boundary above.

An option's OPERAND SHALL NOT be read as an assignment. The variable named by an unset is the opposite of an injection, and reporting `env -u VAR prog` as assigning VAR would invert what the event says. An operand SHALL be taken from the remainder of its own token when there is one and from the next argument otherwise, so that the trailing characters of an attached operand are not themselves read as further options.

An invocation SHALL report no assignments when the argument vector after env's options no longer describes what env applied. Three cases, and in each one the safe direction is the same: an option env does NOT have, because env exits without executing the command and performs none of them; the option that suppresses running a command at all, which env refuses to combine with one; and the option carrying a whole command line as its value, since env re-splits that value and the command it names may consume the tokens that follow as its own arguments.

That asymmetry is the reason the rule SHALL prefer reporting nothing in all three. Reporting nothing risks MISSING an injection, which another detection may still catch. Reporting the run risks FABRICATING one, sending an analyst after an event that did not happen, and this field feeds a high-severity rule.

An option's OPERAND SHALL also be judged where env decides it STATICALLY. An unset of a name env cannot unset, being empty or containing an assignment separator, makes env exit before executing anything, so the assignments after it were never applied. An operand-taking option with no operand at all likewise makes env exit.

The preference for a miss over a fabrication SHALL NOT extend to an operand whose validity depends on the HOST rather than on the argument vector. The working-directory option is refused only when the directory does not exist, which is a property of the host at execution time and usually holds, so treating a named directory as unusable would let an attacker suppress a high-severity finding with one flag. A miss the ATTACKER chooses is worse than a fabrication the environment causes by accident, which is why the preference inverts for exactly this case and no other.

That exception is per VALUE and not per option. An EMPTY working directory is refused whatever the host looks like, so it is decided like any other statically invalid operand; only a named one is left undecided.

For any other executable the system SHALL report no assignments. The invocation name SHALL NOT be scanned for env either, since that is env's own name and not an assignment it performs.

A rule matching any of these fields is portable in the sense that it is valid Sigma, but it depends on a field only this system supplies, and SHALL be reported as such rather than as standard Sigma.

#### Scenario: A rule matches the verb rather than the whole command line

- **GIVEN** a rule keyed on a tool's subcommand
- **WHEN** an event invokes that tool with the named token present but NOT as its subcommand
- **THEN** the rule does not match

#### Scenario: An operand after the verb is matchable

- **GIVEN** a rule requiring both a subcommand and a later argument matching a pattern
- **WHEN** an event supplies both
- **THEN** the rule matches

#### Scenario: A leading assignment is distinguished from a later argument

- **GIVEN** two events carrying the same assignment text, one in leading position and one as an operand of the program
- **WHEN** a rule keyed on the assignment is evaluated against both
- **THEN** it matches only the first

#### Scenario: An option before an assignment does not hide it

- **GIVEN** an exec event for env whose arguments place an option before an assignment
- **WHEN** the assignments are read
- **THEN** the assignment is reported

#### Scenario: An option's operand is not an assignment

- **GIVEN** an exec event for env that unsets a variable by name
- **WHEN** the assignments are read
- **THEN** the unset variable is not reported as assigned

#### Scenario: An assignment after the end-of-options marker belongs to the command

- **GIVEN** an exec event for env whose end-of-options marker is followed by a token that looks like an option
- **WHEN** the assignments are read
- **THEN** that token is treated as the command rather than as an option

#### Scenario: A name a shell would reject does not end the run

- **GIVEN** an exec event for env whose leading assignments include a name no shell would accept, followed by an injection assignment
- **WHEN** the assignments are read
- **THEN** the injection assignment is reported and the malformed name is not

#### Scenario: An attached operand is not read as further options

- **GIVEN** an exec event for env whose option carries its operand attached, with the operand ending in a character that is itself an option letter
- **WHEN** the assignments are read
- **THEN** the following assignment is reported rather than consumed as an operand

#### Scenario: An invocation env would refuse reports no assignments

- **GIVEN** an exec event for env carrying an option env does not have, followed by an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported

#### Scenario: An option suppressing the command reports no assignments

- **GIVEN** an exec event for env carrying the option that refuses to run a command, followed by an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported

#### Scenario: A command line carried as an option value reports no assignments

- **GIVEN** an exec event for env whose option value is a command line, followed by a token that looks like an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported, because that token may be an argument of the command the value names

#### Scenario: An unset of a name env cannot unset reports no assignments

- **GIVEN** an exec event for env unsetting a name that is empty or contains an assignment separator, followed by an assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported, because env exits before executing anything

#### Scenario: An operand whose validity depends on the host does not suppress the finding

- **GIVEN** an exec event for env whose working-directory operand names a directory, followed by an assignment
- **WHEN** the assignments are read
- **THEN** the assignment is reported, because suppressing it would be an attacker-selectable bypass rather than a protection
- **AND** an EMPTY working directory instead reports no assignments, because that one is refused whatever the host looks like

#### Scenario: An assignment with an empty name reports nothing at all

- **GIVEN** an exec event for env whose leading assignments include one with an empty name, followed by an injection assignment
- **WHEN** the assignments are read
- **THEN** no assignment is reported, because env exits before executing anything

#### Scenario: A shell-form assignment is not reported

- **GIVEN** an exec event for an ordinary binary whose first argument looks like an environment assignment
- **WHEN** the assignments are read
- **THEN** nothing is reported, because a shell applies its assignments without passing them as arguments and no agent can produce that event

### Requirement: A converted rule carries its logic in its file

The system SHALL evaluate a detection whose logic is a Sigma `detection:` block in its rule file, rather than a function in the engine.

The system SHALL compile every such block, and check every field it reads against the taxonomy for its logsource category, when the rule catalog is built. A block that does not compile, names a field the event type does not supply, or declares a category for which no fields are supplied SHALL prevent start-up. Deferring any of these to evaluation would produce a rule that loads cleanly and then never matches, which cannot be told apart from the behaviour never occurring.

A rule SHALL declare what decides it in exactly one way: a detection block, or the name of an engine evaluator. Carrying both would point a reader at code that no longer decides anything, and carrying neither leaves a rule file that cannot say what the rule does.

The system SHALL treat a rule's detection block as authored rather than generated, and regeneration SHALL re-emit it unchanged, comments included.

#### Scenario: A detection block is compiled and checked when the pack loads

- **GIVEN** a rule file carrying a detection block that reads a field its event type does not supply
- **WHEN** the rule catalog is built
- **THEN** it fails, naming the field

#### Scenario: A converted rule detects what it detected before

- **GIVEN** a detection converted from an engine implementation
- **WHEN** the events that exercised the original are replayed
- **THEN** it produces the same findings

### Requirement: Portability is derived from the rule rather than declared

The system SHALL derive a rule's kind and portability from the rule itself: whether it carries a detection block, and whether the fields that block reads come from Sigma's own taxonomy or are computed by this engine.

The system SHALL report a rule reading only taxonomy fields as portable to any Sigma-compatible engine, one reading a computed field as valid Sigma that needs fields only this engine supplies, and one with no detection block as not portable at all. Each rule file SHALL state the reason, so a reader of one file in isolation learns why it will or will not run elsewhere.

Portability is a promise made to whoever reads the file about whether they can run the rule, so it is derived rather than asserted by hand.

#### Scenario: Portability is derived from the rule rather than declared

- **GIVEN** a rule whose detection block reads a field this engine computes
- **WHEN** its file is generated
- **THEN** the file reports it as valid Sigma requiring fields only this engine supplies, and explains why

### Requirement: An alert from a converted rule names what fired

The system SHALL describe a finding from a rule whose logic is a detection block using the values that detection matched on, read back from the same fields, so that the text an operator reads cannot drift from the condition that produced it.

The system SHALL NOT include attacker-controlled content in that description where naming the matched element is sufficient. An injected library path identifies nothing the operator needs that the variable name does not, and the description is read in an alert feed, so the value is withheld while the variable is named.

Where a detection matched a list-valued field, the system SHALL name the element that satisfied it rather than the whole list, since the evaluator reports only that some element matched.

#### Scenario: A finding names the matched element rather than the whole field

- **GIVEN** a rule whose detection matched one element of a list-valued field
- **WHEN** the finding is built
- **THEN** its description names that element

#### Scenario: An attacker-supplied value is withheld from the description

- **GIVEN** a rule that fires on an environment assignment
- **WHEN** the finding is built
- **THEN** it names the variable and not the value assigned to it

### Requirement: Converting a rule may narrow what it detects, never widen it

The system SHALL NOT begin alerting on anything a rule did not alert on before its logic moved into its file. Where reading a computed field corrects a matcher's behaviour, the correction SHALL remove findings rather than add them, and SHALL be recorded rather than absorbed silently.

A conversion is offered as behaviour-preserving, so an operator has no reason to re-tune a rule afterwards. A widening breaks that promise in the direction that costs an analyst time; a narrowing that is documented does not.

#### Scenario: A conversion removes a finding rather than adding one

- **GIVEN** a rule whose converted form declines an invocation its previous implementation matched
- **WHEN** the two are compared over generated invocations
- **THEN** every difference is the converted form declining, and none is it firing where the previous implementation did not

### Requirement: A rule declares the mode it operates in absent configuration

A detection MAY declare the mode it operates in when no configuration applies to it. A detection that declares none SHALL operate in `alert`.

A declared default SHALL apply whenever no setting matches the (rule, host) being evaluated, including when no detection-configuration surface is available at all. A configured setting SHALL override a declared default, so that an operator's instruction is never overridden by the rule's own declaration.

When a configured mode cannot be interpreted, the system SHALL apply the declared default rather than alerting. An uninterpretable stored value is not an instruction to alert; alerting would promote a rule whose author declared otherwise on the strength of a value the system could not read. A severity override accompanying an uninterpretable mode SHALL still be honoured, being legible when the mode is not.

A declared default SHALL be reported by the operator-facing rule catalog, and SHALL be distinguishable there from a mode resolved from configuration. The rule-settings surface lists only settings an operator created, so a rule left at its own default appears on no other surface and would otherwise be indistinguishable from one that alerts.

#### Scenario: A rule declaring no default alerts

- **GIVEN** a registered detection that declares no default mode
- **WHEN** a finding it produces is routed and no setting applies to it
- **THEN** the finding is persisted as an alert

#### Scenario: A rule declaring a default operates in it when nothing is configured

- **GIVEN** a registered detection that declares `monitor` as its default mode
- **WHEN** a finding it produces is routed and no setting applies to it
- **THEN** no alert is persisted and the would-be detection is recorded as an observability signal

#### Scenario: A configured setting overrides a declared default

- **GIVEN** a registered detection that declares `monitor` as its default mode, and an operator setting for it whose mode is `alert`
- **WHEN** the mode for that detection is resolved
- **THEN** the resolved mode is `alert`, not the declared `monitor`

<!-- The claim stops at resolution on purpose. What happens to a finding once its mode is `alert` belongs to the
"Operator toggling of individual rules" requirement, which already specifies and tests it, and no package can assert both halves
here: the real snapshot lives inside the rules context and the engine inside the detection context, so a test reaching both would
have to fake one of them and would then be pinning the fake. -->

#### Scenario: An uninterpretable configured mode falls back to the declared default

- **GIVEN** a stored setting whose mode is a value this build does not recognise, for a detection that declares `monitor`
- **WHEN** the mode for that detection is resolved
- **THEN** the resolved mode is `monitor` rather than `alert`
- **AND** a severity override carried by that setting is still returned

#### Scenario: A declared default is listed on the rule catalog

- **GIVEN** a registered detection that declares a default mode
- **WHEN** an operator reads the rule catalog surface
- **THEN** the entry for that detection reports the mode it operates in absent configuration

### Requirement: A rule is invoked only for batches carrying an event type it consumes

The system SHALL evaluate a rule against a batch only when that batch carries at least one event of a type the rule declares it consumes, so that the cost of a batch depends on the rules that can act on it rather than on the size of the catalog.

A rule's declared event types SHALL act as a trigger filter and not as a batch filter: a rule that is invoked SHALL receive the whole batch, because a rule triggered by one event type may read another from the same batch to build its finding. Narrowing the batch to the triggering type would silently degrade those rules.

The system SHALL NOT exclude a rule that declares no event types from dispatch, whatever event types a batch carries. Skipping a rule that had something to do loses a detection with no error and no alert, whereas invoking one that had nothing to do costs only time, so the engine SHALL resolve this asymmetry in favour of running the rule.

Dispatch decides only whether a rule is offered a batch. Whether that rule then evaluates remains governed by the platform scoping applied to every rule, which this leaves unchanged: a rule left with no events after scoping evaluates nothing, as before.

Dispatch SHALL preserve the order in which rules were registered, because the engine reports the first retryable error it encounters and reordering would change which rule is named to the operator.

#### Scenario: A rule is not invoked for a batch it cannot act on

- **GIVEN** a rule that declares it consumes only one event type
- **WHEN** a batch arrives carrying none of that type
- **THEN** the rule is not invoked, and no span is recorded for it

#### Scenario: A triggered rule still sees the whole batch

- **GIVEN** a rule triggered by one event type that reads a second type to build its finding
- **WHEN** a batch carrying both arrives
- **THEN** the rule receives every event in the batch, not only those of the triggering type

#### Scenario: A rule declaring no event types still runs

- **GIVEN** a registered rule that declares no event types
- **WHEN** a batch is evaluated carrying only event types that rule never named
- **THEN** the rule is invoked, because dispatch is an optimisation and must not drop a detection

#### Scenario: A batch left with no events evaluates no rule

- **GIVEN** a batch whose events are all filtered out before evaluation
- **WHEN** it is evaluated
- **THEN** no rule evaluates it, which is what happened before dispatch existed

### Requirement: A rule declares the event types it consumes

Every registered rule SHALL declare at least one event type, and each declared type SHALL be one the agent actually emits. A rule declaring nothing forfeits dispatch, and one declaring a type that is never emitted would never be invoked at all.

A rule's declaration SHALL cover every event type it reads. A rule that reads a type it does not declare would be skipped for batches carrying only that type, and the findings it would have produced are lost silently, so the declaration is verified against the rule's behaviour rather than trusted.

#### Scenario: A rule that declares no event types is refused

- **GIVEN** a registered rule whose declaration names no event type
- **WHEN** the catalog is checked
- **THEN** it fails, naming the rule

#### Scenario: A rule finds nothing in a batch of types it does not declare

- **GIVEN** a registered rule and a batch made entirely of event types it does not declare
- **WHEN** the rule evaluates that batch
- **THEN** it produces no findings, so skipping it for such a batch loses nothing

### Requirement: A rule that does not run records no span

The system SHALL determine that a rule has nothing to evaluate before opening that rule's span, so that per-rule spans describe work that actually happened. A span emitted for a rule that was handed no events reports evaluation that did not occur and inflates per-rule span volume by every rule the batch could never reach.

A rule that IS evaluated SHALL still carry its span with the rule identifier and the resulting alert count, because those attributes are what let detection latency and alert volume be grouped by rule.

#### Scenario: A rule scoped out by platform records no span

- **GIVEN** a rule targeting a platform no event in the batch carries
- **WHEN** the batch is evaluated
- **THEN** no span is recorded for that rule

### Requirement: Evaluation statistics are aggregated in process and written periodically

The system SHALL NOT write per-rule evaluation statistics to the database while processing an event batch. Those statistics SHALL be aggregated per replica in memory and written on a periodic flush and on graceful shutdown.

The write is synchronous and every replica contends on the same database instance, so performing it per batch bounded the batches per second a whole deployment could process however many replicas were added. An observability feature SHALL NOT bound the data plane.

The aggregate SHALL be exact with respect to what the per-batch writes would have accumulated: counts and total durations add, and the worst single evaluation takes the larger of the two rather than the more recent.

That exactness covers the COUNTERS of any window that is successfully written. The times a statistics row carries are taken when it is written, so deferring the write attributes work up to one flush interval later than it happened, and work in the final seconds of a day can be recorded against the next one. This is a bounded and accepted difference, not an exactness claim: the interval is seconds against a window read in days, so no decision the numbers exist for turns on it.

A failed flush SHALL discard that window rather than retrying it, and the system SHALL report the loss.

Retrying was tried and rejected, and the reason belongs here because it is not obvious. The write is an ADDITIVE upsert, so a retry is at-least-once: a commit whose result never reaches the client is added again, repeated failures are not bounded to one window, and because later work merges in between attempts the derived mean moves rather than staying put. Neither retrying nor discarding yields exact totals once the database is failing, so the choice goes to the one whose behaviour can be stated in a sentence. Making the write idempotent is the only thing that would make it exact under failure, and that is a schema question tracked separately.

Statistics are therefore lost in three conditions, all of which SHALL be documented where an operator reading the table would look: a failed flush, including the final one on shutdown; an ungraceful shutdown; and work recorded after the final flush, since the evaluation workers are not joined to it. Each is bounded by one flush window.

Buffering is acceptable for these statistics and SHALL NOT be extended to monitor match counts. A monitor match is a fact about the world that drives a promotion decision, so losing one makes a rule look quieter than it is; an evaluation cost sample is one of thousands and losing a window changes no decision.

This requirement constrains WHEN the durable record is written and what that costs. It does not weaken the separate observability requirement that the record exists durably per rule and survives the process: a lost window is a gap in a durable record, not a return to reporting from a span.

Per-rule evaluation duration SHALL additionally be reported as a metrics histogram, so the question of which rule is slow is answerable with percentiles rather than only from the durable table. It SHALL measure the same duration the durable table records, INCLUDING time spent reading the process graph: a rule slow through its reads is as much an operator problem as one slow through matching, and two surfaces answering one question with different quantities is worse than either choice. The evaluation budget continues to exclude that time, for the different purpose of not letting a slow datastore disable rules.

#### Scenario: Processing a batch performs no statistics write

- **GIVEN** a replica processing many event batches
- **WHEN** each batch's per-rule statistics are recorded
- **THEN** no statistics are written to the database
- **AND** the recorded work is still held for a later flush

#### Scenario: A flush writes the exact aggregate

- **GIVEN** several batches recorded for the same rule since the last flush
- **WHEN** the flush runs
- **THEN** one row per rule is written whose counts and total duration are the sums, and whose worst single evaluation is the largest of them

#### Scenario: A graceful shutdown writes what it had accumulated

- **GIVEN** a replica holding unflushed statistics
- **WHEN** it is shut down gracefully
- **THEN** the statistics are written before it exits

#### Scenario: A failed flush discards that window and reports it

- **GIVEN** a replica holding unflushed statistics and a database that rejects the write
- **WHEN** the flush fails
- **THEN** that window is discarded rather than retried, and the failure names how many rules' statistics were lost
- **AND** statistics recorded after the failure are written by the next successful flush, unaffected by it

#### Scenario: Evaluation duration is available as a histogram per rule

- **GIVEN** a rule evaluated against a batch
- **WHEN** the evaluation completes
- **THEN** its duration is recorded on a metrics histogram attributed to that rule

### Requirement: Rules written in the Sigma format are evaluated against a single event

The system SHALL evaluate a rule expressed as a Sigma `detection:` block, combining its named searches with its condition, against one event at a time.

The system SHALL hold no state between events while evaluating such a rule. Aggregation and correlation appear in none of the 3,141 rules of the upstream corpus, so there is no construct that requires remembering an earlier event.

The system SHALL compare values case-insensitively, as the Sigma specification defines, except under the `re` modifier, whose expression is applied verbatim so that an author who wants case-insensitivity requests it inline. Folding case there would silently widen every imported rule that relies on it.

The system SHALL support wildcards in plain values, where `*` matches any run of characters and `?` exactly one. These carry no modifier and are used by 31 of the 69 macOS rules, so a rule set without them would misread nearly half the corpus.

The system SHALL treat a backslash before `*`, `?` or a backslash as an escape, comparing the escaped character literally. 47 corpus rules escape a wildcard, and an escaped wildcard evaluated as a live one matches far more than the rule says, which surfaces as extra alerts rather than as an error.

The system SHALL fold case using Unicode simple case folding, the same equivalence the plain-value comparison uses, so that adding a wildcard to a value cannot change which characters it is considered equal to.

#### Scenario: A rule matches an event that satisfies its condition

- **GIVEN** a rule whose searches and condition describe a behaviour
- **WHEN** an event satisfying them is evaluated
- **THEN** the rule matches

#### Scenario: A filter search suppresses a match

- **GIVEN** a rule of the form `selection and not 1 of filter_*`
- **WHEN** an event satisfies both the selection and a filter
- **THEN** the rule does not match

#### Scenario: An escaped wildcard is matched literally

- **GIVEN** a rule whose value escapes a wildcard character
- **WHEN** an event carrying that literal character is evaluated
- **THEN** the rule matches, and it does not match a value where the escaped character stands for any text

#### Scenario: Values are compared without regard to case

- **GIVEN** a rule matching a value in one case
- **WHEN** an event carries that value in another case
- **THEN** the rule matches

### Requirement: An unsupported or meaningless rule construct is refused when the rule is loaded

The system SHALL refuse to load a rule that uses a modifier it does not implement, naming the field and the modifier.

The system SHALL refuse to load a rule whose condition names a search that does not exist, or whose `1 of` or `all of` pattern matches no search. Such a rule evaluates to a constant false, so it would load cleanly and then detect nothing for as long as it remained installed, which is indistinguishable from the behaviour never occurring.

The system SHALL refuse to load a rule whose field matcher combines constructs with no defined meaning together, such as a regular expression with a substring modifier, or a null value with any modifier.

The system SHALL refuse to load a rule whose search declares no values to match, since an empty list matches nothing under the default quantifier and everything under `all`.

The system SHALL refuse to load a rule whose field matcher combines two substring modifiers, or repeats one. They have no composed meaning, and letting the last one win would make two orderings of the same modifiers compile to different matchers, neither of them what the author wrote.

The system SHALL refuse to load a rule that uses a reserved Sigma key inside its detection block as though it were a search. Compiled as a search, such a key would also be swept into any quantifier, so the rule would evaluate a condition nobody wrote instead of being refused for using a construct the evaluator does not implement.

The system SHALL bound how deeply a condition may nest and refuse one that exceeds the bound. Parsing recurses once per level, so an unbounded condition would exhaust the stack and terminate the process during loading, in the very path whose contract is to return an error.

Each refusal SHALL identify the rule element at fault. Refusing at load rather than at match time is the point: an unsupported construct that was merely ignored would leave a rule that still evaluates, matching far more broadly than its author wrote, which produces confident wrong alerts rather than a visible failure.

#### Scenario: A rule using an unimplemented modifier is refused

- **GIVEN** a rule whose field matcher uses a modifier the evaluator does not implement
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the field and the modifier

#### Scenario: A condition naming an undefined search is refused

- **GIVEN** a rule whose condition references a search the rule does not define
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the undefined search

#### Scenario: A reserved detection key is not treated as a search

- **GIVEN** a rule whose detection block carries a reserved Sigma key alongside its searches
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the unsupported construct

#### Scenario: A condition nested beyond the bound is refused

- **GIVEN** a condition nested more deeply than the parser admits
- **WHEN** the rule is loaded
- **THEN** loading fails with an error rather than exhausting the stack

#### Scenario: A quantifier matching no search is refused

- **GIVEN** a rule whose condition quantifies over a pattern matching none of its searches
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the pattern

### Requirement: A rule compiles to the same evaluation on every load

The system SHALL resolve a condition's search references and quantifier patterns deterministically, independent of the order in which the rule's searches were decoded.

Go randomises map iteration, and a Sigma `detection:` block decodes to a map. Without a defined order, `all of selection_*` could resolve to a different set of searches on each start, and the resulting intermittent detection would be attributed to the rule rather than to the loader.

#### Scenario: Repeated loads of one rule resolve identically

- **GIVEN** a rule whose condition quantifies over several searches
- **WHEN** it is loaded repeatedly
- **THEN** its searches resolve in the same order every time

### Requirement: Detections are exportable as declarative rule files

The system SHALL render each registered detection as a declarative rule file carrying the rule's human-readable title, a stable identifier, its description, its severity, its MITRE ATT&CK technique identifiers, the platform and event category it applies to, its known false-positive sources, the event types it consumes, the exclusion dimensions it honours, and its known limitations.

The file SHALL name the evaluator that decides the rule. A rule whose logic is an implementation rather than a declarative expression is otherwise documented only by what it is for, never by what it does, and the evaluator name is what an operator cannot obtain without reading source.

The system SHALL NOT export a registered rule that is not a detection, for the reasons the catalog surface already omits them: a rule with no detection logic, no tuning surface, and no adversary claim has nothing to describe in a rule file.

The system SHALL state in each exported file why the rule will or will not run on another engine, so a reader of one file in isolation is not left to infer its portability.

Rendering SHALL fail rather than emit a partial file when a rule's metadata cannot produce a complete document. A rule file silently missing its severity or its event category reads as authoritative and is not.

#### Scenario: A detection exports as a rule file

- **GIVEN** a registered detection
- **WHEN** an operator requests its rule file
- **THEN** the file carries the rule's title, identifier, description, severity, techniques, event types, and limitations
- **AND** it names the evaluator that decides the rule

#### Scenario: A non-detection has no rule file

- **GIVEN** a registered rule that declares itself a projection or a health signal
- **WHEN** an operator requests its rule file
- **THEN** no rule file is produced for it

#### Scenario: Incomplete metadata is refused rather than half-rendered

- **GIVEN** a rule whose metadata omits the platform or the event types the file requires
- **WHEN** the system renders it
- **THEN** rendering fails and no partial file is produced

### Requirement: The exported rule pack matches the registered detections

The system SHALL keep the generated rule pack in agreement with the registered detections, covering exactly the detections that are registered and carrying their current content.

A pack that has drifted SHALL fail the build. A stale rule file is the more dangerous half of drift: a missing file is noticed the moment someone looks for it, whereas a file whose description or severity lags the rule reads as current and is wrong.

#### Scenario: A rule added without regenerating the pack fails the build

- **GIVEN** a detection registered with no corresponding file in the pack
- **WHEN** the pack is checked
- **THEN** the check fails and names the regeneration command

#### Scenario: A stale rule file fails the build

- **GIVEN** a rule file in the pack whose content no longer matches the registered rule
- **WHEN** the pack is checked
- **THEN** the check fails and identifies the stale file

### Requirement: The export serves the document a rule was loaded from

When a registered rule was loaded from a rule document, the system SHALL export that document verbatim, and SHALL resolve it from the rule set the deployment currently has in force rather than by matching the rule's identifier against content embedded in the build.

The set in force means the one the rule catalog reports, which during a content reload is briefly ahead of the one detection is evaluating: installing a new set replaces the catalog's copy before rebuilding what evaluation derives from it, and evaluations already running finish on the generation they started with. The export SHALL follow the catalog, so that a rule read alongside the catalog agrees with it, and that bounded divergence is accepted rather than closed, since closing it would require serialising the per-batch evaluation path against a write that happens only when content changes.

The distinction is not academic. A rule's identity is its file stem rather than its path, so an operator who stores their own version of a shipped detection keeps that detection's identifier and the rule that evaluates is theirs. An identifier resolved against the build's own copy still finds the shipped document under that stem, so the export returns content the deployment is not running and the operator did not write. The export exists to answer "what is running here", and it is reached for precisely when someone doubts the answer, so returning a plausible wrong document is worse than returning nothing.

The system SHALL distinguish a rule that came from no document from one whose document is empty. A rule expressed in code was never a file, and the system SHALL render a document for it rather than exporting zero bytes.

The rule and the metadata describing it SHALL be resolved from ONE generation of the active rule set. The two are read together on every export, the set is replaced wholesale when rule content reloads, and a reload landing between two separate reads leaves the system describing a rule the deployment is no longer running. That is not a cosmetic inconsistency: for a rule loaded from a document, its metadata alone renders to nothing, so the export fails rather than reporting a stale answer.

Exporting a document an OPERATOR wrote SHALL require the authorization that reading rule content requires, and exporting one that shipped with the product SHALL NOT. Until the export served the running document it could only return the product's own content, so the authorization that reads the rule catalog was the whole gate; the same gate over an operator's own rule hands it to roles that are refused it on the surface built for rule content. Requiring the stricter authorization for every rule would instead withdraw export of the shipped rules from roles that already read them on the catalog.

The system SHALL NOT decide what to export by asking whether a rule is upstream's. Whether a rule carries a document and whose rule it is are separate questions with different answers for an operator's own rule content, and one predicate answering both will be wrong for whichever question it was not written for.

#### Scenario: A rule an operator overwrote exports as theirs

- **GIVEN** a deployment where an operator has stored their own rule document under the identifier of a rule the build ships
- **WHEN** they export that rule
- **THEN** they receive the document they stored, byte for byte
- **AND** they do not receive the shipped document the build still carries under that identifier

#### Scenario: Exporting an authored rule needs more access

- **GIVEN** a reader authorized to read the rule catalog but not to read rule content
- **WHEN** they export a rule an operator wrote on that deployment
- **THEN** the request is refused
- **AND** exporting a rule that shipped with the product still succeeds for them

#### Scenario: A rule expressed in code is rendered

- **GIVEN** a registered detection written in code, which was never loaded from a document
- **WHEN** an operator exports it
- **THEN** a declarative rule file is rendered for it
- **AND** the response is not an empty document

### Requirement: An open event supplies the writer and the meaning of the write

The system SHALL supply, for a file-open event, the image of the process performing the open, whether the open carried write access, and whether it carried a flag that changes the file's contents.

Write access and mutating intent SHALL be supplied as separate facts rather than combined into one. A rule may need to suppress a specific writer that opens a file write-mode without changing it, which is a test on the second fact conditioned on the writer, and a single combined field cannot express it: collapsing them either loses the suppression or applies it to every writer.

A rule that reads these fields SHALL be reported as valid Sigma requiring fields only this engine supplies. Sigma's file taxonomy models a completed creation or modification rather than an open with flags, so it has no field for the intent behind an open.

#### Scenario: A write-mode open that changes nothing is distinguished from one that does

- **GIVEN** two opens of the same watched path by the same process, one taking a write-mode lock and one truncating the file
- **WHEN** a rule reads the mutating-intent field
- **THEN** it sees them as different, though both carried write access

#### Scenario: The writing process image is available to a file rule

- **GIVEN** a file-open event
- **WHEN** a rule matches on the image of the process that opened the file
- **THEN** it sees the path of that process

### Requirement: A rule suppresses a named exception rather than branching on the writer

The system SHALL let a rule state an exception as a named set of field tests its condition subtracts, so that a suppression conditional on one writer is expressed in the rule file rather than in engine code.

A suppression written this way SHALL apply only to events matching every test in it. A writer other than the named one, performing the same open, SHALL still match the rule.

#### Scenario: The suppression applies only to the writer it names

- **GIVEN** a rule suppressing a write-mode open by one named process that does not change file contents
- **WHEN** a different process performs an identical open of the same path
- **THEN** the rule matches

### Requirement: A detection can be an upstream Sigma file with nothing added

The system SHALL load a rule from a Sigma file that carries no engine-specific keys, deriving what it needs from what Sigma already defines: the rule's identifier from the file name, its target platforms from the log source product, the event types it consumes from the log source category, its severity from its level, and its technique mapping from its tags.

Requiring any additional key would fork the upstream corpus, because a file that must be edited cannot be re-synced without a conflict and its provenance can no longer be checked against upstream.

Operator tuning of an imported rule SHALL live outside the rule file, so that re-syncing the file does not discard it.

#### Scenario: An unmodified upstream rule loads and fires

- **GIVEN** a Sigma rule file taken unchanged from an upstream corpus
- **WHEN** it is imported and an event it describes is evaluated
- **THEN** the rule produces a finding carrying the severity its level maps to

### Requirement: A rule this sensor cannot run is refused by name

The system SHALL refuse to import a rule it cannot run, and SHALL report the reason. Importing it anyway would install a detection that can never match, which is indistinguishable from the behaviour never occurring.

A rule SHALL be refused both when it reads data this sensor does not collect, and when its category maps to an event type the sensor collects too narrowly for that category's rules to fire. The second is not a property of the rule but of the agent, so its reason SHALL name the missing telemetry rather than the rule, and the refusal SHALL be revisited when the agent's collection widens.

Refusing one rule SHALL NOT refuse the rest. An upstream corpus is written for many sensors, so some of its rules will always read data this one does not collect, and abandoning the import over them would import nothing.

A file that cannot be read or parsed, or that claims an identifier another file already claimed, SHALL fail the import rather than being reported as a rejection: those mean the import itself is broken rather than that one detection does not fit.

A detection block the evaluator cannot compile SHALL be classified by WHY it cannot. A rule using a construct the evaluator has not implemented SHALL be refused like any other rule this sensor cannot run. A detection block that is structurally invalid SHALL fail the import, because a vendored file the evaluator cannot parse is a defect in this repository rather than a rule that does not fit.

#### Scenario: A rule reading an unavailable field is refused, and the others still import

- **GIVEN** a corpus in which one rule reads a field this sensor does not collect
- **WHEN** the corpus is imported
- **THEN** that rule is reported as refused, naming the field, and every other rule imports

#### Scenario: A rule using an unimplemented Sigma feature is refused, not a failed import

- **GIVEN** an upstream rule whose detection block is valid Sigma but uses a feature the evaluator does not implement, such as a keyword search
- **WHEN** the corpus is imported
- **THEN** that rule is reported as refused, naming the feature, and every other rule imports

#### Scenario: A structurally invalid detection block fails the import

- **GIVEN** a vendored rule file whose detection block names a search that does not exist
- **WHEN** the corpus is imported
- **THEN** the import fails and names the file, rather than reporting the rule as refused

#### Scenario: Two files claiming one identifier fail the import

- **GIVEN** two rule files that resolve to the same identifier
- **WHEN** the corpus is imported
- **THEN** the import fails, rather than one file silently replacing the other

### Requirement: A launchd-parented chain names pid 1 and can be suppressed

A shell-chain finding whose shell was started directly by pid 1 SHALL name `/sbin/launchd` as the chain's parent, and SHALL be suppressed by a parent-path-glob exclusion matching it.

Pid 1 is what such a shell's parent IS on macOS, so naming it is a statement of fact rather than a synthetic stand-in for a missing process row. That is what makes the exclusion meaningful: an operator writing a glob for it is excluding the thing the alert names.

The system SHALL NOT report a claimed parent process id of 0 as pid 1. Process 0 is the kernel, so naming it launchd would state something false, and would let an exclusion written for launchd silence a chain that was never launchd's.

A finding with no resolved parent process row SHALL remain unsuppressable by a SIGNATURE exclusion, whether or not its parent is nameable. With no row there is no signing identity to read, and reporting one would contradict the requirement that an unsigned binary at a benign-looking path is never silently allowed.

Suppressing this class is BROAD by nature, and the system SHALL state that where an operator would act on it. An exclusion matching pid 1 silences every launchd-started shell chain for that rule, which includes real persistence execution; the breadth is a property of suppressing the class rather than of how the parent is named, so it is documented rather than designed away.

#### Scenario: A launchd-parented chain names pid 1

- **GIVEN** a shell started directly by pid 1 whose chain would otherwise raise a finding
- **WHEN** the rule evaluates it
- **THEN** the finding names `/sbin/launchd` as the chain's parent rather than reporting the parent as unnameable

#### Scenario: A launchd-parented chain can be suppressed by a parent path exclusion

- **GIVEN** a shell started directly by pid 1 whose chain would otherwise raise a finding
- **AND** a parent-path-glob exclusion matching pid 1's path for that rule
- **WHEN** the rule evaluates it
- **THEN** no finding is produced

#### Scenario: An exclusion for another path leaves a launchd-parented chain firing

- **GIVEN** a shell started directly by pid 1 whose chain would otherwise raise a finding
- **AND** a parent-path-glob exclusion for some other path for that rule
- **WHEN** the rule evaluates it
- **THEN** the finding is still produced, because suppression is no broader than what the operator wrote

#### Scenario: A claimed parent of process 0 is not named as pid 1

- **GIVEN** a shell claiming a parent process id of 0
- **WHEN** the rule evaluates it
- **THEN** the parent is reported as unnameable rather than as pid 1
- **AND** an exclusion matching pid 1's path does not suppress it

### Requirement: Network arm resolves a shell that exec'd its payload in place

The `suspicious_exec` rule's outbound-network arm SHALL resolve its shell ancestor from the connecting PID's own exec chain when the PPID chain yields no shell the arm can fire on, in addition to the existing PPID walk. A shell that executes its payload without forking replaces its own image at the same PID, which closes the shell generation and removes it from the connecting process's ancestry, so an arm that consults only the PPID chain cannot see it. The exec arm already resolves this shape through the same chain.

The fall-through to the chain MUST trigger when the PPID walk produces no shell the arm can fire on, not only when it produces no shell at all. Where a shell exec'd in place, the walk does not terminate empty: it returns the next shell above, typically the interactive login shell, whose own exec is far older than the rule's window. A condition that reached the chain only on an empty walk would therefore never reach it in the case the chain exists to serve.

A shell resolved from the exec chain SHALL be subject to the same gates as one resolved from the PPID chain: the trigger event must fall within the shell's window, the shell's non-shell parent must not match an operator exclusion, and a shell already reported in the batch must not be reported twice. The chain is a second place to look for the shell, never a relaxation of when the rule fires.

#### Scenario: A shell execs its payload in place and the payload connects out

- **GIVEN** a non-shell parent spawns a shell that replaces its own image with the payload at the same PID, with an interactive login shell far above it in the PPID chain whose exec is outside the rule's window
- **WHEN** the payload makes an outbound connection and the engine evaluates the batch
- **THEN** the engine produces a `suspicious_exec` finding naming the shell that ran the payload and the non-shell parent above it
- **AND** the finding links to the connecting process, so an analyst opening the alert lands on the payload rather than on the shell

#### Scenario: The shell on the exec chain is outside the window

- **GIVEN** a shell that exec'd its payload in place, whose own exec is older than the rule's window at the time of the outbound connection
- **WHEN** the engine evaluates the batch
- **THEN** the engine produces no finding, because consulting the exec chain does not relax the window

#### Scenario: A re-exec with no shell on the chain does not fire

- **GIVEN** a non-shell process that replaced its image with another non-shell binary at the same PID, which then connects out
- **WHEN** the engine evaluates the batch
- **THEN** the engine produces no finding, because the arm looks for a shell on the chain rather than for the presence of a re-exec

### Requirement: A rule can match on the parent process

The system SHALL make the executing process's parent image available to a detection as a field, so a rule can condition on what spawned a process without reaching into the process graph itself.

The system SHALL resolve that image only when a rule reads it, and at most once per event. A detection that reads the parent image reaches it after cheaper conditions have already narrowed the events, so resolving eagerly would read the process graph for every execution on the host.

The system SHALL resolve that image when the rule is evaluated rather than when the event is stored. Processes are materialized before rules run and events are stored before that, so a value written at storage time would be missing for any process whose parent arrived in the same batch, and would be missing permanently.

The system SHALL report the field as absent when the parent cannot be resolved, so a rule keyed on a parent declines rather than matching a process whose image is unknown.

The system SHALL distinguish a parent that does not exist from a lookup that failed. Both leave the field absent, and only the second means the answer is unknown rather than negative, so the failure SHALL be reported to the rule rather than presented as an absent parent. (What the engine then does with that error is out of scope here: it currently isolates it like any other rule error, which issue #798 covers.)

The evaluator SHALL NOT itself depend on the process graph. The value is supplied to it, which keeps matching semantics testable against literal values and keeps the lookup where the retry behaviour lives.

#### Scenario: The parent image is supplied by the caller

- **GIVEN** an exec event whose parent the caller has resolved
- **WHEN** a rule matching on the parent image is evaluated
- **THEN** it sees the resolved path

#### Scenario: An unresolvable parent declines rather than matching

- **GIVEN** an exec event whose parent cannot be resolved
- **WHEN** a rule matching on the parent image is evaluated
- **THEN** the rule does not match, and the failure is reported to the rule rather than read as an absent parent

### Requirement: The vendored upstream corpus is registered and does not alert until promoted

The system SHALL register the upstream detection rules it vendors alongside the rules it authors, so they evaluate against live events.

Each vendored rule SHALL operate in `monitor` by default, recording what it would have fired on without persisting an alert, until an operator promotes it. The system did not author these rules and cannot vouch for their behaviour on a given fleet; a catalog that raises alerts an operator has no basis to trust loses the alerts that were right along with the ones that were not.

Every operator-facing surface that describes the catalog SHALL distinguish a rule that does not alert from one that does. In particular, a coverage export SHALL NOT represent a technique covered only by non-alerting rules the same way it represents one covered by an alerting rule, because such a document is read as a claim about what the product raises.

A vendored rule SHALL be attributed. Its upstream project and the rule's own author SHALL be reported wherever the catalog is described to an operator, because a vendored rule is otherwise presented exactly as one this project wrote and a reader cannot tell them apart. A rule this project authored SHALL report this project as its attribution rather than reporting none: attribution now also rides the alert view, where an absent credit cannot be distinguished from a credit that failed to arrive, and the two populations remain distinguishable by the value.

A vendored rule's declarative form SHALL be the file that was vendored. The system SHALL NOT emit a second rendering of it in its own format, and a request to export such a rule SHALL return the vendored bytes.

Guards that enforce this project's authoring standards SHALL apply to the rules it authors. Where a vendored rule falls outside one, the exception SHALL be recorded by name, so that scoping a guard costs visibility rather than concealing the gap.

#### Scenario: The vendored corpus is registered alongside the rules this project authored

- **GIVEN** a vendored upstream corpus whose rules this sensor can run
- **WHEN** the rule catalog is built
- **THEN** every runnable vendored rule is registered, and the rules this project authored are registered as well

#### Scenario: A vendored rule raises no alert until an operator promotes it

- **GIVEN** a registered vendored rule and no operator setting for it
- **WHEN** an event it matches is evaluated
- **THEN** no alert is persisted and the match is recorded as an observability signal

#### Scenario: Coverage from non-alerting rules is not claimed as coverage

- **GIVEN** one technique covered only by rules that do not alert, and another covered by a rule that does
- **WHEN** the ATT&CK coverage layer is built
- **THEN** the two are given different scores, and the first is annotated as raising no alert until promoted

#### Scenario: A vendored rule is attributed on the operator-facing catalog

- **GIVEN** a registered vendored rule and a registered rule this project authored
- **WHEN** an operator reads the rule catalog surface
- **THEN** the vendored rule's entry names its upstream project and that rule's author
- **AND** the authored rule's entry names this project

#### Scenario: Exporting a vendored rule returns the upstream file

- **GIVEN** a registered vendored rule
- **WHEN** an operator exports it
- **THEN** the response is the vendored file's bytes rather than a rendering of the rule in this project's format

#### Scenario: A vendored rule outside an authoring standard is recorded by name

- **GIVEN** a vendored rule that claims no ATT&CK technique, or whose title does not meet this project's naming standard
- **WHEN** the catalog guards run
- **THEN** the rule is named in the recorded set of exceptions, and a change to that set fails the guard

### Requirement: An alert credits the author of the rule that raised it

Every registered detection SHALL name an origin. A detection that declares no upstream SHALL be credited to this project; a detection that declares an upstream but names no author SHALL be credited to neither, since claiming such a rule as this project's work would credit the wrong party. Attribution is therefore total, and a surface displaying it need not decide what to render when it is absent.

An alert SHALL record the attribution of the detection that raised it, as of the moment it was raised. The system SHALL derive that attribution from the detection rather than from the finding, so that a detection cannot forge, reassign, or suppress its own credit.

Recorded attribution SHALL NOT change when the detection it names is later re-credited, removed, or replaced. Resolving attribution from the catalog when an alert is displayed would leave an alert whose detection has since left the catalog displaying no credit at all, which is the outcome the requirement exists to prevent.

Every surface that displays an alert SHALL display its attribution, as rendered text rather than as a hover affordance. A credit revealed only on hover is not available to a reader scanning a list, printing it, or using an assistive technology that does not announce it.

An alert that records no attribution SHALL be displayed without a credit rather than with an invented one. Alerts raised before attribution was recorded carry none, and substituting a default would assert something the alert does not record.

#### Scenario: An alert from a vendored rule credits its author

- **GIVEN** a registered vendored detection that names an upstream project and author
- **WHEN** it raises an alert and an operator views that alert
- **THEN** the alert displays the upstream project and that rule's author

#### Scenario: An alert from a rule this project wrote credits this project

- **GIVEN** a registered detection that declares no upstream
- **WHEN** it raises an alert and an operator views that alert
- **THEN** the alert displays this project as the rule's author

#### Scenario: A rule declaring an upstream but naming no author is not claimed as ours

- **GIVEN** a registered detection that declares an upstream source and names no author
- **WHEN** its attribution is resolved
- **THEN** the attribution names neither this project nor an author

#### Scenario: Attribution recorded on an alert survives the rule being re-credited

- **GIVEN** an alert raised by a detection crediting one author
- **WHEN** that detection is subsequently re-credited to a different author
- **THEN** the existing alert still displays the author it was raised with

#### Scenario: An alert recording no attribution displays no credit

- **GIVEN** an alert that records no attribution
- **WHEN** an operator views it
- **THEN** no credit is displayed for it

### Requirement: A detection's references are available beside its attribution

A detection SHALL carry the sources it was written from, and the operator-facing catalog SHALL report them. A vendored detection's references are the upstream rule's own, so that a credit can be checked against the work it credits rather than being taken on trust.

A reference SHALL be presented as a followable link only when it is an `http` or `https` URL. References on a vendored detection are third-party content, and presenting an arbitrary scheme as a link makes a citation into a means of execution. A reference that is not such a URL SHALL still be displayed, without being followable.

#### Scenario: An upstream reference is offered as a link

- **GIVEN** a registered vendored detection citing an `https` URL
- **WHEN** an operator reads that detection's documentation
- **THEN** the citation is displayed and is followable

#### Scenario: A reference carrying an executable scheme is displayed but not followable

- **GIVEN** a registered detection whose citation uses a scheme other than `http` or `https`
- **WHEN** an operator reads that detection's documentation
- **THEN** the citation is displayed and is not followable

### Requirement: A rule whose identifier cannot be persisted is refused at load

Every surface that stores a rule identifier SHALL accept the full length the system permits a rule identifier to be, and that permitted length SHALL be defined in one place that both the storage and the validation agree on.

A rule whose identifier exceeds the permitted length SHALL be refused when the rule set is loaded, and the refusal SHALL name the rule and the limit. It SHALL NOT be registered, and it SHALL NOT be presented to an operator as a rule they can configure or promote.

Refusing at load rather than discovering the problem at write time is the point of this requirement. A rule whose identifier is too long for the alert table cannot raise an alert, and the failure does not degrade gracefully: persisting an alert is not isolated per rule, so the error fails the batch, the batch is nacked and re-claimed, and nothing caps the attempts. A single such rule matching on a host therefore stops that host's event queue from draining at all, which ends detection for that host rather than for that rule. Presenting such a rule as promotable offers the operator an action whose consequence is a detection outage.

The identifier's permitted length SHALL leave headroom above the longest identifier the system ships, so that importing an upstream rule corpus does not require a schema change, and the refusal SHALL be the mechanism that catches an identifier beyond that headroom.

#### Scenario: An over-long identifier is refused when the rule set loads

- **GIVEN** a rule whose identifier is longer than the permitted length
- **WHEN** the rule set is loaded
- **THEN** loading fails with an error naming that rule and the limit
- **AND** the rule is not registered

#### Scenario: Every shipped rule identifier is storable

- **GIVEN** the rule set the system ships
- **WHEN** each rule's identifier is measured against the permitted length
- **THEN** every identifier is within it

#### Scenario: A rule with a long identifier can raise an alert

- **GIVEN** a rule in alert mode whose identifier is longer than 64 characters
- **WHEN** the rule matches an ingested event
- **THEN** the alert is persisted and readable
- **AND** the batch is acknowledged rather than nacked and replayed

### Requirement: Detection parameters are read from the rule pack

The system SHALL read each detection's match values and decision thresholds from its rule file rather than from compiled-in constants, so that what a rule matches can be inspected and changed without reading or rebuilding source.

The system SHALL validate every parameter against a schema registered for the rule's evaluator rather than for the rule itself. Two rules sharing an evaluator therefore cannot disagree about which parameters it accepts, and one parameter name may mean different things under different evaluators without being reconciled.

The system SHALL refuse to start when a rule sets a parameter its evaluator never reads. A parameter nothing consults is worse than a missing one, because it invites an operator to believe they have tuned something.

The system SHALL refuse to start when a rule omits a parameter its evaluator reads, when a duration is unparseable or not positive, or when a match list is empty. Each refusal SHALL name the rule. Validation happens when the pack is loaded, so a bad value fails at start-up rather than at first fire, on one host, as a detection that silently did not happen.

The system SHALL NOT expose parameters that bound retrieval rather than the decision. Widening such a bound changes no finding and only widens a scan, while narrowing it causes silent false negatives, so no setting improves detection.

#### Scenario: A rule reads its match values from its file

- **GIVEN** a detection whose file declares its match values
- **WHEN** the engine loads the rule pack
- **THEN** the rule matches against the values in the file

#### Scenario: A parameter the evaluator never reads is refused

- **GIVEN** a rule file setting a parameter its evaluator does not read
- **WHEN** the pack is loaded
- **THEN** loading fails, naming the rule and the parameter

#### Scenario: A malformed parameter is refused at load

- **GIVEN** a rule file whose parameter is unparseable, not positive, or an empty match list
- **WHEN** the pack is loaded
- **THEN** loading fails, naming the rule

### Requirement: Values shared between rules are defined once

The system SHALL hold a match value used by more than one detection in a single shared definition rather than a copy in each rule's file.

Copying a shared value into every consumer's file leaves nothing keeping the copies equal, which is a weaker guarantee than the single definition it replaced. A value read by one rule belongs to that rule; a value read by code shared across rules belongs to the shared definitions.

The shared definitions are authored rather than generated, and the system SHALL preserve them when regenerating the pack.

#### Scenario: A shared value has one definition

- **GIVEN** a match value more than one detection uses
- **WHEN** an operator inspects the rule pack
- **THEN** the value is defined once and read by every consumer

#### Scenario: Regenerating the pack preserves the shared definitions

- **GIVEN** a rule pack containing authored shared definitions
- **WHEN** the pack is regenerated from the registered detections
- **THEN** the shared definitions are left intact

### Requirement: Rules tolerate a process stamped after an event that followed it

A rule that attributes an event to a process SHALL tolerate the process being recorded with a timestamp LATER than an event which must causally have followed it, up to a bounded pad. An outbound connection cannot precede the process that opened it, and a payload cannot precede the shell that ran it, so a small negative delta is evidence of a late stamp rather than evidence of no relationship.

The tolerance SHALL be applied where the two stamp sources meet, which is the comparison between the triggering event and the shell, and MUST NOT be applied to a parent edge. A parent SHALL be resolved at the instant its CHILD forked, because that is the only instant at which the question has an answer. Resolving a parent edge at an unrelated later instant asks which process holds that PID now, and widening such a lookup forward is worse than not tolerating skew at all: a PID reused after the child forked would answer as the child's parent, fabricating an ancestor chain from an unrelated process. A parent edge needs no tolerance in any case, because a child's fork and its parent's fork come from the same event stream and so run late together, preserving their order.

The rule's shell window SHALL apply the tolerance to its LOWER bound only. The upper bound is a real limit on how long after a shell the rule still attributes activity to it and MUST NOT be widened.

The tolerance MUST remain bounded. A shell whose recorded exec is far beyond the pad after the trigger is not a late stamp, and attributing the trigger to it would make the rule's window meaningless.

This exists because an agent that stamps events when its handler finishes, rather than from the kernel's own event time, records a process exec after the network connection that process opened. Stamping from kernel time removes the cause at the source, but hosts run older agents until they upgrade and some handler latency always remains.

#### Scenario: A shell is recorded as exec'ing after the connection it opened

- **GIVEN** a non-shell parent spawns a shell whose recorded exec time falls after the outbound connection made from beneath it, by less than the tolerated pad
- **WHEN** the engine evaluates the batch
- **THEN** the engine resolves the shell and produces a `suspicious_exec` finding naming it
- **AND** the finding is produced without widening the window's upper bound

#### Scenario: A shell far beyond the pad is still rejected

- **GIVEN** a shell whose recorded exec time falls after the trigger by far more than the tolerated pad
- **WHEN** the engine evaluates the batch
- **THEN** the engine produces no finding, because that separation is not a late stamp

#### Scenario: A child is not attributed to a generation that recycled its parent's PID

- **GIVEN** a process whose parent exited and whose parent's PID was then reused by an unrelated process, after the child forked
- **WHEN** the engine resolves that child's ancestry while evaluating a later event
- **THEN** the resolved parent is the generation that was alive when the child forked, not the generation that recycled the PID

### Requirement: Replacing the active rule set is atomic

The system SHALL treat the active rule set as one immutable value and replace it atomically, so that a batch being evaluated while the set is replaced is evaluated against exactly one set. Evaluation SHALL take its view of the rules once and use that view throughout, so the indices it dispatches on and the rules it invokes can never come from different sets.

This is a precondition for loading rule packs at runtime rather than a preference. The processor evaluates batches from concurrent workers, and the dispatch indices are derived state rebuilt whenever the rules change, so replacing the rules while a batch is in flight would otherwise let one evaluation read indices built for a set it is no longer holding. The consequence is not a crash but a WRONG evaluation: a rule invoked for a batch that does not carry its event types, or worse, a rule skipped for one that does.

Replacement SHALL have replace semantics, not append, so a set loaded repeatedly does not accumulate duplicates of the same rule and evaluate it more than once per batch.

The derived indices SHALL remain reproducible from the rules alone, so they stay a per-replica cache in the sense ADR-0010 permits: they hold nothing a peer replica would need to serve the next request, and are rebuilt on load rather than shared.

#### Scenario: A batch evaluated during a replacement sees one consistent rule set

- **GIVEN** batches being evaluated concurrently while the active rule set is replaced repeatedly
- **WHEN** a replacement lands between an evaluation's dispatch decision and its invocation of the selected rules
- **THEN** that evaluation invokes rules from a single set, and every rule it invokes is one that set declared for the batch's event types
- **AND** no evaluation observes a partially replaced set

#### Scenario: Loading the active set repeatedly does not duplicate rules

- **GIVEN** an engine whose active rule set has already been loaded
- **WHEN** it is loaded again with the same rules
- **THEN** each rule appears once and is evaluated once per batch

### Requirement: EDR sensor tamper detection

Disabling security tooling is a recognised technique, and the product has never detected it being used against itself. The system SHALL register a `sensor_tamper` rule that raises a finding when one of the EDR's own capture providers stops.

The finding SHALL carry no ATT&CK technique. The rule reports a provider that stopped and did not come back, and a crash produces that state identically, so it cannot observe the actor that Impair Defenses names. Deciding that is the ATT&CK attribution sweep's, and it is stated here rather than left for the sweep's delta alone, because a requirement mandating the technique would archive alongside the one forbidding it and leave the canonical spec contradicting itself.

The rule SHALL be evaluated against the durable capture-provider transition records rather than against agent health. Health is level state, and the agent repairs a stopped provider automatically, so by the time an analyst looks the health view reports the host healthy and no trace remains that capture was ever off.

A stop SHALL NOT produce a finding when capture for the same provider resumes within a short recovery window. This is what separates a routine agent upgrade from tampering: replacing the system extension stops its providers, and the platform reports the same stop reason for that as for somebody switching capture off, so the reason cannot be the discriminator. The replacement provider resumes about a second later, whereas a stop that needed the agent's repair takes tens of seconds. The rule MUST NOT decide on the platform's stop reason.

The rule SHALL NOT conclude that capture failed to resume until the recovery window has elapsed, because a resumption inside the window has to reach the server before it can be observed. An undecided stop SHALL be re-evaluated rather than reported early, and the wait SHALL be bounded so a stop whose recovery never arrives is still reported.

A finding SHALL cite the stop it fired on and SHALL identify the provider, so an analyst can tell which telemetry stream the host stopped reporting. Repeated evaluation of one stop SHALL collapse to a single alert, while a separate stop SHALL raise its own.

A provider an operator has deliberately disabled SHALL NOT produce a finding. The agent reports a supported opt-out as the provider being absent rather than stopped, and records no transition for it, so no suppression list is involved.

The rule reports that capture stopped, NOT whether it was later restored. Whether the repair succeeded, is still pending, or gave up is carried by the subsequent transition records, and none of it is known at the time the stop must be reported. Gating the finding on the outcome would suppress the most serious case, a provider that never comes back at all.

#### Scenario: A capture provider stops and does not resume

- **GIVEN** a host reporting a capture provider running
- **WHEN** that provider stops and capture does not resume within the recovery window
- **THEN** the engine produces one `sensor_tamper` finding
- **AND** that finding carries no ATT&CK technique
- **AND** the finding names the provider and cites the stop record

#### Scenario: An upgrade cutover does not fire

- **GIVEN** a capture provider that stops while the agent's system extension is being replaced
- **AND** the stop carries the same platform reason a deliberate disable carries
- **WHEN** capture for that provider resumes within the recovery window
- **THEN** the engine produces no `sensor_tamper` finding

#### Scenario: A stop is not judged before its recovery window elapses

- **GIVEN** a stop record that reaches the engine before its recovery window has elapsed
- **WHEN** the engine evaluates it and finds no resumption yet
- **THEN** the engine does not produce a finding for it yet and re-evaluates it later
- **AND** the engine reports the stop once the window has elapsed with no resumption

#### Scenario: A deliberately disabled provider does not fire

- **GIVEN** an operator has disabled an optional capture provider
- **WHEN** the agent reports its providers
- **THEN** no stop record exists for that provider and the engine produces no `sensor_tamper` finding

### Requirement: Rules evaluating one batch derive shared work once

The engine SHALL offer every rule evaluating one batch the same per-batch scratch space, so that rules deriving the same thing from the same events derive it once rather than once each.

The scratch space SHALL be opaque to the engine, which SHALL NOT depend on what any rule derives into it. It SHALL live for exactly one batch evaluation, so that no derived value survives a request and concurrent batch evaluations share nothing.

Using it SHALL be optional. A rule that derives nothing shareable SHALL be evaluated unchanged, and a rule SHALL produce the same findings whether or not it is given a scope.

Work derived through the scratch space SHALL be shared only where sharing is observationally equivalent. In particular, an error from a deferred lookup SHALL reach only the rules that requested that lookup, because such an error discards the requesting rule's findings for the whole batch and must not discard those of a rule that never made the request.

#### Scenario: Every rule in one batch is offered the same scope

- **GIVEN** two rules that both derive a value from the batch under the same key
- **WHEN** the engine evaluates one batch containing an event both rules consume
- **THEN** the second rule receives the value the first derived, rather than deriving it again

#### Scenario: A later batch does not see an earlier batch's derivations

- **GIVEN** a rule that derives a value from the batch
- **WHEN** the engine evaluates a second batch
- **THEN** the rule derives the value again, because the scratch space did not outlive the first batch

#### Scenario: A rule that does not use the scope is unaffected

- **GIVEN** a registered rule that derives nothing from the batch
- **WHEN** the engine evaluates a batch it consumes
- **THEN** the rule is evaluated and its findings are collected as before

#### Scenario: One event is decoded once however many rules read it

- **GIVEN** several Sigma-backed rules that all read fields of the same event
- **WHEN** the engine evaluates the batch containing it
- **THEN** the event's payload is decoded once and its process-graph lookups are performed once

#### Scenario: A failed lookup reaches only the rule that asked for it

- **GIVEN** two Sigma-backed rules reading the same event, where only one reads a field resolved from the process graph, and that lookup fails
- **WHEN** the engine evaluates the batch
- **THEN** the rule that read the field reports the failure and the rule that did not is unaffected

### Requirement: An event a rule cannot identify a subject for is skipped

A rule SHALL skip an event whose payload does not decode, or which carries no process identifier, rather than acting on it or failing the batch.

Such an event cannot be attributed to a process, so there is nothing for a finding to name, and it SHALL NOT be treated as an error: an error from a rule's per-event evaluation discards the findings that rule has already collected from the rest of the batch, so one malformed event from one host would cost every other alert in the batch.

#### Scenario: A malformed event does not discard the batch's findings

- **GIVEN** a batch containing an event whose payload does not decode, followed by an event a rule fires on
- **WHEN** the rule evaluates the batch
- **THEN** the malformed event is skipped and the finding from the later event is still produced

#### Scenario: An event carrying no process identifier is skipped rather than attributed to process zero

- **GIVEN** an event whose payload omits the process identifier
- **WHEN** a rule evaluates it
- **THEN** the event is skipped, rather than a process lookup being performed for identifier zero

### Requirement: Independently tunable chain shapes are separate rules

Where one rule would detect two chain shapes that an operator would want to tune, promote, or silence independently, those shapes SHALL be separate rules. Exclusions, modes and severities are keyed by rule identity, so two shapes under one identity cannot be configured apart: silencing a noisy source for one blinds the other.

This does NOT require a rule to consume a single event type. A rule correlating one chain across several kinds of event is one shape, and declaring every type it acts on is correct for it. What the requirement forbids is one rule answering to two shapes an operator would treat differently.

A rule SHALL declare exactly the event types it acts on. The engine dispatches on that declaration, so a type declared but never acted on wastes evaluation, and a type acted on but not declared means the rule is never invoked for the batches it would have matched, silently.

Where one attribution chain exhibits the signals of more than one rule, each rule SHALL raise its own finding. The system SHALL NOT suppress one rule's finding on the strength of another's: rules cannot observe each other's output, and a precedence encoded inside one rule is alert grouping in the wrong layer.

An exclusion SHALL apply only to the rule it names. Two rules covering related shapes therefore carry separate exclusion sets, and an operator who has silenced one has not silenced the other.

A rule separated out of an existing rule SHALL default to `monitor`. It inherits none of the exclusions operators saved against the rule it came from, so it begins unfiltered where that rule had been tuned; defaulting it to alert would re-raise every false positive its predecessor had already absorbed, on upgrade, with no operator action. It is promoted once its own false-positive rate has been observed.

#### Scenario: A chain exhibiting both signals raises one alert per rule

- **GIVEN** a non-shell process that spawns a shell which both execs from a world-writable directory and opens an outbound connection within the window, and both rules resolved to alert
- **WHEN** the batch is evaluated
- **THEN** the temp-exec rule raises a finding and the outbound-connect rule raises a finding, each under its own rule identity

#### Scenario: An exclusion saved against one arm does not silence the other

- **GIVEN** an exclusion naming the temp-exec rule and matching the chain's non-shell parent
- **WHEN** a chain exhibiting both signals is evaluated
- **THEN** the temp-exec rule raises nothing and the outbound-connect rule still raises its finding

#### Scenario: A rule separated out of another ships in monitor

- **GIVEN** a rule separated out of an existing rule, carrying none of that rule's saved exclusions
- **WHEN** its default mode is inspected
- **THEN** it reports `monitor`, so it raises no alert until an operator promotes it

#### Scenario: A rule correlating one chain across several event types is unaffected

- **GIVEN** a registered rule that correlates a single chain across process, DNS and network events
- **WHEN** its declaration is inspected
- **THEN** it declares all three event types, and is not required to be split

### Requirement: One exec-chain walk for both shell-chain rules

The rules that look for a shell on a process's own exec chain SHALL share one walk. Two copies of the same graph traversal drift, and a divergence between them decides whether a payload is detected at all depending on which rule sees it first.

The walk SHALL prefer the newest suitable generation on the chain. Where a shell replaced itself more than once, the generation closest to the payload is the one that ran it; the oldest is the most likely to fall outside the window, so preferring it loses chains whose newer shell was well within it.

The walk SHALL NOT report a shell whose claimed parent is absent from the graph. Exclusions match on the parent's path, so a finding naming an unresolved parent cannot be suppressed by an exclusion an operator has configured for it, and an alert that recurs with no way to silence it drives an operator to disable the rule entirely, losing every detection it makes rather than this one. A shell parented at the init process is a genuine no-parent case, not incomplete ancestry, and still counts.

A declined chain SHALL be observable per rule. A rule that reports nothing because an ancestor was missing is otherwise indistinguishable from a rule with nothing to report, which is how detection coverage rots without anyone noticing; the trade this requirement makes has to be measurable against the rule's own alert volume, or there is no evidence on which to revisit it. The count SHALL reflect only chains declined for missing ancestry: a chain the rule declines for any other reason is its ordinary intended behaviour, and counting it would report ancestry as a problem on every host that merely runs long-lived shells.

The chain is DROPPED, not retried. This is the skip semantics the "Retryable evaluation on unmaterialized subject process" requirement already specifies for ancestor and parent-chain lookups: the retryable class covers the pid an event is about, not its ancestry. A parent record arriving later does not recover the detection, and the requirement here does not promise that it will.

#### Scenario: The newest suitable generation on the chain is preferred

- **GIVEN** a chain where a shell replaced itself twice before running a payload, the older generation outside the window and the newer inside it
- **WHEN** the batch is evaluated
- **THEN** the chain is reported, and the finding names the newer generation

#### Scenario: A declined chain is counted against the rule that declined it

- **GIVEN** two rules sharing one exec-chain walk, one of which declines a chain for incomplete ancestry
- **WHEN** the batch is evaluated
- **THEN** the decline is recorded against that rule's own identity, and not against the rule it shares the walk with

#### Scenario: A chain declined for any other reason is not counted as incomplete ancestry

- **GIVEN** a chain whose shell resolves its parent, but which the rule declines for an unrelated reason such as the shell falling outside the window
- **WHEN** the batch is evaluated
- **THEN** no ancestry decline is recorded, so the count reflects only what requiring resolved ancestry costs

#### Scenario: A shell whose parent is absent from the graph is not reported

- **GIVEN** a chain whose shell generation claims a parent that has no record in the graph, and whose parent is not the init process
- **WHEN** the batch is evaluated
