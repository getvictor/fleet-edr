# Detection rules engine

## ADDED Requirements

### Requirement: One chain shape per rule

A rule SHALL detect one chain shape and declare exactly the event type that triggers it. A rule detecting two shapes cannot be tuned, promoted, or silenced for one of them, and the engine dispatches on the declared event types, so a declaration wider than the rule can act on wastes evaluation while one narrower than it acts on silently loses detections.

Where one attribution chain exhibits the signals of more than one rule, each rule SHALL raise its own finding. The system SHALL NOT suppress one rule's finding on the strength of another's: rules cannot observe each other's output, and a precedence encoded inside one rule is alert grouping in the wrong layer.

An exclusion SHALL apply only to the rule it names. Two rules covering related shapes therefore carry separate exclusion sets, and an operator who has silenced one has not silenced the other.

#### Scenario: A chain exhibiting both signals raises one alert per rule

- **GIVEN** a non-shell process that spawns a shell which both execs from a world-writable directory and opens an outbound connection within the window
- **WHEN** the batch is evaluated
- **THEN** the temp-exec rule raises a finding and the outbound-connect rule raises a finding, each under its own rule identity

#### Scenario: An exclusion saved against one arm does not silence the other

- **GIVEN** an exclusion naming the temp-exec rule and matching the chain's non-shell parent
- **WHEN** a chain exhibiting both signals is evaluated
- **THEN** the temp-exec rule raises nothing and the outbound-connect rule still raises its finding

## MODIFIED Requirements

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch of its target platform: `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `shell_network_connect`, `dns_c2_beacon`, `sensor_tamper`, `application_control_block`, and `sensor_recovery_failed`. The registered-rule metadata SHALL report each rule's target platforms.

The operator-facing catalog SHALL report the registered rules that are detections. Registration and evaluation are unchanged for the rest: a registered rule that is not a detection is still evaluated against every batch of its target platform and still persists its findings as alerts.

The change from the prior requirement is that the catalog an operator inspects reports detections only, rather than every registered rule, and that `application_control_block` joins the registration list. It was registered and evaluated all along but was never named here, which was harmless while registration and the catalog were the same thing. Now that they differ, leaving it out would let the spec permit dropping its alerts entirely.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_network_connect`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, and `sensor_tamper`

#### Scenario: Rule metadata reports target platforms

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the registered-rule metadata
- **THEN** each rule reports the operating-system platforms it targets

## ADDED Requirements

The list additionally names `shell_network_connect`, the outbound-connection shape separated from `suspicious_exec` so each can be tuned and promoted on its own.

### Requirement: Version-agnostic parent allowlist matching

The `suspicious_exec` rule's non-shell parent allowlist (configured by `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST`) SHALL match an allowlist entry against the candidate parent process path treating the `*` character as a wildcard that matches any run of characters including the path separator. An entry that contains no `*` MUST match only by exact string equality, preserving the behavior of existing literal-path configurations. A candidate whose non-shell parent matches an allowlist entry is suppressed for the rule the entry names, and a finding with no resolved non-shell parent is never suppressed by the allowlist. Entries are per rule: since the temp-exec and outbound-connect shapes became separate rules, an entry saved against one does not suppress the other.

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

### Requirement: Local-resolver DNS suppression for the outbound-connect rule

The `suspicious_exec` rule MUST NOT treat an outbound `network_connect` event to remote port 53 as a triggering outbound connection when the event's `remote_address` parses as a local-resolver-class IP address: an IPv4 or IPv6 loopback address, an RFC1918 private address, an IPv4 link-local address, an address in the CGNAT range `100.64.0.0/10`, an IPv6 unique-local address, or an IPv6 link-local address. An outbound connection to port 53 whose `remote_address` is any other (publicly routable) address MUST still be eligible to trigger the network arm. This suppression applies only to the outbound-network arm; it does not affect the temp-path-exec arm.

#### Scenario: Outbound DNS to a local resolver does not count as a network connection

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `100.100.100.100` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces no `suspicious_exec` finding from the network arm, because the destination is the host's local-resolver-class address on the DNS port

#### Scenario: Outbound DNS to a public resolver still fires

- **GIVEN** a non-shell parent spawns a shell that issues an outbound `network_connect` to `8.8.8.8` on port 53
- **WHEN** the engine evaluates the rule against the batch
- **THEN** the engine produces a `suspicious_exec` finding from the network arm, because the destination is a publicly routable address
