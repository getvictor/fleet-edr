# Agent XPC receiver specification (delta)

## ADDED Requirements

### Requirement: Distinct signal when a sysext upgrade leaves the NE registration stale

When the agent cannot establish the network-extension XPC connection AND the operating system reports a previous network-extension version pending removal on reboot (a staged upgrade), the agent SHALL emit a distinct, actionable signal indicating that a reboot is required to complete the extension cutover, rather than the generic connect-failure warning. The generic warning SHALL remain for the not-yet-approved case, where no previous version is pending removal. The distinct signal SHALL be emitted at most once per stale episode and SHALL reset when the connection is next established.

#### Scenario: NE connect keeps failing while a prior version waits to uninstall on reboot

- **GIVEN** a system-extension upgrade has been staged and the previous network-extension version is waiting to uninstall on reboot
- **AND** the agent's network-extension receiver cannot establish its XPC connection
- **WHEN** the receiver has failed to connect past the grace threshold
- **THEN** the agent emits the distinct reboot-required signal
- **AND** it does not repeat the signal on every subsequent failed attempt within the same episode

#### Scenario: A not-yet-approved network extension keeps the generic warning

- **GIVEN** no previous network-extension version is pending removal on reboot
- **AND** the agent's network-extension receiver cannot establish its XPC connection
- **WHEN** the receiver fails to connect
- **THEN** the agent emits the generic connect-failure warning and not the upgrade-reboot signal
