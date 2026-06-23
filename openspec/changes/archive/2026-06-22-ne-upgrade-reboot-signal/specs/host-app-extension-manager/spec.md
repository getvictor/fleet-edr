# Host app extension manager specification (delta)

## ADDED Requirements

### Requirement: A staged upgrade surfaces a reboot-required signal

When an activation request reports that it will complete after reboot (the operating system is deferring removal of a previous extension version), the host app SHALL surface a distinct operator-facing signal that a reboot is required to finish the upgrade and restore network and DNS coverage. A fresh activation that completes without a deferred reboot SHALL NOT surface this signal.

#### Scenario: Activation will complete after reboot

- **GIVEN** an activate invocation
- **WHEN** at least one extension request reports it will complete after reboot
- **THEN** the host app surfaces the reboot-required signal
- **AND** the host app still exits successfully so the activation is not retried prematurely

#### Scenario: Fresh activation does not prompt for reboot

- **GIVEN** an activate invocation
- **WHEN** every extension request completes without a deferred reboot
- **THEN** the host app does not surface the reboot-required signal
