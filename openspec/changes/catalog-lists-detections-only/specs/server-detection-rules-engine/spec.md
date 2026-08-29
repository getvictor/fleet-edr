# Server detection rules engine: catalog lists detections only delta

## MODIFIED Requirements

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch of its target platform: `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, `sensor_tamper`, and `sensor_recovery_failed`. The registered-rule metadata SHALL report each rule's target platforms.

The operator-facing catalog SHALL report the registered rules that are detections. Registration and evaluation are unchanged for the rest: a registered rule that is not a detection is still evaluated against every batch of its target platform and still persists its findings as alerts.

The change from the prior requirement is that the catalog an operator inspects reports detections only, rather than every registered rule.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, and `sensor_tamper`

#### Scenario: Rule metadata reports target platforms

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the registered-rule metadata
- **THEN** each rule reports the operating-system platforms it targets

## ADDED Requirements

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
