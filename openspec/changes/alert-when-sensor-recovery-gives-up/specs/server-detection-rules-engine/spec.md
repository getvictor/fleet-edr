# Server detection rules engine: recovery-failure alerting delta

## MODIFIED Requirements

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch of its target platform: `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, `sensor_tamper`, and `sensor_recovery_failed`. The registered-rule metadata SHALL report each rule's target platforms.

The change from the prior requirement is the addition of `sensor_recovery_failed`, the second rule whose subject is the EDR itself.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, `dns_c2_beacon`, `sensor_tamper`, and `sensor_recovery_failed`

#### Scenario: Rule metadata reports target platforms

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the registered-rule metadata
- **THEN** each rule reports the operating-system platforms it targets

## ADDED Requirements

### Requirement: EDR sensor recovery failure detection

A stopped capture provider that the agent cannot restore leaves the host not reporting that telemetry until a person intervenes, and the existing stop finding cannot say so: it is raised seconds after the stop, when the outcome is not yet known, and it therefore reads identically for a host that repaired itself and one that did not. The system SHALL register a `sensor_recovery_failed` rule that raises a finding when the agent reports that its automatic repair of a capture provider has exhausted its attempts, carrying the `T1562.001` technique.

The finding SHALL carry a higher severity than the stop finding that precedes it, because a stop may already have been repaired by the time an analyst looks whereas this state persists until someone acts.

The finding SHALL name the provider to restore and SHALL report how many repair attempts were made, so it is distinguishable from a repair that was never attempted.

The finding SHALL report which failure shape was reached, because they implicate different parts of the host: the repair command failing points at the host application or the configuration daemon, while every repair reporting success and the provider staying stopped means re-enabling is not what the fault needs. An outcome the server does not recognise SHALL still produce a finding, described in general terms rather than dropped, so that a newer agent reporting a new shape is not silently unreported.

The rule SHALL NOT wait or re-evaluate before deciding. Unlike the stop finding, whose meaning depends on what happens next, its input reports a settled outcome.

Repeated evaluation of one exhaustion SHALL collapse to a single alert, while a separate exhaustion SHALL raise its own.

A provider an operator has deliberately disabled SHALL NOT produce a finding. The agent does not attempt to repair a provider reported as a supported opt-out, so no record exists for it to evaluate.

#### Scenario: Automatic recovery gives up and raises a finding

- **GIVEN** a host whose capture provider stopped
- **WHEN** the agent reports that its repair attempts for that provider are exhausted
- **THEN** the engine produces one `sensor_recovery_failed` finding carrying the `T1562.001` technique
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
