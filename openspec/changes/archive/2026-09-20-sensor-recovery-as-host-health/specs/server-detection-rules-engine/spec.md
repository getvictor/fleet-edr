## MODIFIED Requirements

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch of its target platform: `suspicious_exec`, `shell_network_connect`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, `sensor_tamper`, `application_control_block`, `application_control_would_block`, and `sensor_recovery_failed`. The registered-rule metadata SHALL report each rule's target platforms.

The operator-facing catalog SHALL report the registered rules that are detections. Registration and evaluation are unchanged for the rest: a registered rule that is not a detection is still evaluated against every batch of its target platform.

Where its findings are RECORDED depends on what kind of non-detection it is, and the rule declares that kind itself. A projection renders a decision that was already made about activity on the host, so, like a detection's findings, its findings follow the mode the rule runs in: `application_control_block` renders a denied exec and persists alerts that are worked in the same queue as detections, and `application_control_would_block` renders an exec the policy allowed that a `DETECT` application-control rule matched, and declares monitor, so its findings are kept as monitor records, and its matches are counted under the application-control rule each finding names, the rule an operator decides whether to promote. A health signal reports a fault in this product's own software, so its findings are recorded as host health episodes and SHALL NOT persist as alerts: an operational fault in the queue an analyst works to decide whether the host is under attack is a claim the rule is not making. A registered rule that declares no kind is a detection and persists its findings as alerts, which is what every rule that says nothing continues to do.

The changes from the prior requirement are that a non-detection's findings are no longer uniformly persisted as alerts: the destination now follows the declared kind, so a health signal is recorded as a host health episode while a projection is recorded in its mode; and the addition of `application_control_would_block`, which gives application-control Detect mode a place to record what a rule would have blocked.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_network_connect`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, and `sensor_tamper`

#### Scenario: Rule metadata reports target platforms

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the registered-rule metadata
- **THEN** each rule reports the operating-system platforms it targets

#### Scenario: A health signal is recorded as an episode rather than an alert

- **GIVEN** a registered rule that declares itself a health signal
- **WHEN** that rule produces a finding
- **THEN** a host health episode is recorded for the finding's host
- **AND** no alert row is created for it

#### Scenario: A projection is still an alert

- **GIVEN** a registered rule that declares itself a projection and runs in alert mode
- **WHEN** that rule produces a finding
- **THEN** the finding persists as an alert, as a detection's would

#### Scenario: A would-block match is kept as a monitor record

- **GIVEN** an `application_control_would_block` event naming a process the graph knows
- **WHEN** the engine evaluates the batch
- **THEN** a monitor record is kept under the matched application-control rule's id, with that rule's severity
- **AND** the match is counted under that rule's id
- **AND** no alert is created for it

### Requirement: EDR sensor recovery failure detection

A stopped capture provider that the agent cannot restore leaves the host not reporting that telemetry until a person intervenes, and the existing stop finding cannot say so: it is raised seconds after the stop, when the outcome is not yet known, and it therefore reads identically for a host that repaired itself and one that did not. The system SHALL register a `sensor_recovery_failed` rule that raises a finding when the agent reports that its automatic repair of a capture provider has exhausted its attempts.

The finding SHALL be recorded as a host health episode rather than as an alert. Both outcomes it can report name this product's own software, so it establishes nothing about an adversary and does not belong in the queue an analyst works to decide whether a host is under attack. Its urgency is unchanged by the move: a host that is not capturing needs someone to act whether or not anyone attacked it.

The finding SHALL carry no ATT&CK technique, and its text SHALL name none either. The rule's own documentation sends an analyst to this product's components as the likely cause of what it reports, so there is no actor for it to attribute. Stated here as well as in the change that decided it, because a requirement mandating the technique would archive alongside the one forbidding it.

The finding SHALL carry a higher severity than the stop finding that precedes it, because a stop may already have been repaired by the time an analyst looks whereas this state persists until someone acts.

The finding SHALL name the provider to restore and SHALL report how many repair attempts were made, so it is distinguishable from a repair that was never attempted. Those facts SHALL reach the episode as fields rather than only inside its prose, because the surface that reads them is a health record rather than an analyst reading a description.

The finding SHALL report which failure shape was reached, because they implicate different parts of the host: the repair command failing points at the host application or the configuration daemon, while every repair reporting success and the provider staying stopped means re-enabling is not what the fault needs. An outcome the server does not recognise SHALL still produce a finding, described in general terms rather than dropped, so that a newer agent reporting a new shape is not silently unreported.

The rule SHALL NOT wait or re-evaluate before deciding. Unlike the stop finding, whose meaning depends on what happens next, its input reports a settled outcome.

Repeated evaluation of one exhaustion SHALL collapse to a single episode, whether or not that episode has closed in between, while a separate exhaustion SHALL open its own.

An operator's mode setting for this rule SHALL be honoured as it is for any other rule: a rule an operator disabled records nothing. The rule is absent from the tunable catalog, but the settings API does not validate a rule id against the registered set, so such a setting can exist and ignoring it would silently override a deliberate choice.

A provider an operator has deliberately disabled SHALL NOT produce a finding. The agent does not attempt to repair a provider reported as a supported opt-out, so no record exists for it to evaluate.

Alerts this rule raised before it became a health signal SHALL be left as they are. They are the only record of the episodes they describe, and rewriting them would have to invent a resolution time nobody observed.

#### Scenario: Automatic recovery gives up and opens a health episode

- **GIVEN** a host whose capture provider stopped
- **WHEN** the agent reports that its repair attempts for that provider are exhausted
- **THEN** the engine produces one `sensor_recovery_failed` finding
- **AND** that finding carries no ATT&CK technique
- **AND** the finding names the provider and reports how many repairs were attempted
- **AND** the finding is recorded as an open host health episode rather than as an alert

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

### Requirement: Non-detections are excluded from the operator-facing catalog

A registered rule MAY declare that it is not a detection, and SHALL state which kind it is: a `projection` of a decision made elsewhere, or a `health` signal about the sensor itself. A rule that declares nothing SHALL be treated as a detection, so that the common case requires no declaration and cannot be omitted from the catalog by oversight.

The system SHALL omit non-detections from the operator-facing rule catalog, from the ATT&CK coverage export, and from the generated rule documentation. Those surfaces describe detections an operator reads, tunes, and reasons about; a rule with no detection logic offers a tuning surface that does not exist, and one that makes no adversary claim inflates a coverage figure that is read during procurement.

The system SHALL NOT change how a non-detection is registered or evaluated. The declared kind decides only where its findings are RECORDED, which the registered-rule-catalog requirement states: a projection is recorded in the mode it runs in, as a detection is, and a health signal is recorded as a host health episode. Identifiers and severities are unchanged in either case.

The change from the prior requirement is that persistence is no longer uniform across non-detections. It previously held that a non-detection "continues to raise the same alerts", which was true while the only recording surface was the alerts table and is what issue #778 changed for health signals and application-control Detect mode changed for a projection that runs in monitor.

#### Scenario: The catalog omits a non-detection

- **GIVEN** a registered rule that declares itself a projection or a health signal
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** that rule is absent from the catalog
- **AND** it is absent from the ATT&CK coverage export

#### Scenario: A non-detection still evaluates

- **GIVEN** a registered rule that declares itself a projection or a health signal
- **WHEN** the engine evaluates a batch that satisfies it
- **THEN** the rule is evaluated and its finding is recorded, with the identifier and severity the rule gave it
- **AND** which surface it is recorded on follows the kind it declares

#### Scenario: A rule that declares nothing is a detection

- **GIVEN** a registered rule that makes no non-detection declaration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** that rule is present in the catalog
