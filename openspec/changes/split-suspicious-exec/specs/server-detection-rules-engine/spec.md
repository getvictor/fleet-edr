# Detection rules engine

## ADDED Requirements

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

## MODIFIED Requirements

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
