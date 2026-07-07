## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch of its target platform: `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, and `dns_c2_beacon`. The registered-rule metadata SHALL report each rule's target platforms.

The change from the prior requirement is that rule metadata now reports each rule's target platforms, and a rule is evaluable against batches of its declared platform rather than unconditionally.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, and `dns_c2_beacon`

#### Scenario: Rule metadata reports target platforms

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the registered-rule metadata
- **THEN** each rule reports the operating-system platforms it targets
