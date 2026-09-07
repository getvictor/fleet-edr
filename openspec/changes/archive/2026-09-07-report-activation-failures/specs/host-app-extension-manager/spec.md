# Host app extension manager: operator-facing activation reporting delta

## ADDED Requirements

### Requirement: Activation outcomes are reported to the operator

The host app's activation command is run both by a human and by the install path's activation service, and its exit code is frequently the only signal either one has. It SHALL therefore report what happened, not merely exit with a status.

Every terminal outcome of an extension request SHALL be reported on the command's output: that it was submitted, that it completed, that it will complete after a reboot, that it is awaiting approval, and that it failed. A failure SHALL carry the reason it failed.

Failures SHALL be reported on the error stream rather than the standard output stream, so a caller that captures or redirects normal output still observes them.

Where an outcome is also written to the system log, the message SHALL be readable there. Values that are not sensitive SHALL NOT be recorded in a form that redacts them, because a reason nobody can read is not a diagnostic.

#### Scenario: A failed activation states why

- **GIVEN** an extension activation request that the system rejects
- **WHEN** the operator runs the activation command
- **THEN** the command exits non-zero
- **AND** the reason for the failure is written to the error stream
- **AND** the same reason is readable in the system log

#### Scenario: Awaiting approval is reported rather than silent

- **GIVEN** a host where the extension requires user approval
- **WHEN** the activation command submits its request
- **THEN** the command reports that it is waiting for approval
- **AND** it remains running while the request is pending

#### Scenario: A successful activation still reports its result

- **GIVEN** a host where the extension activates
- **WHEN** the operator runs the activation command
- **THEN** the command reports the outcome and exits zero
