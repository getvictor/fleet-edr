# Host App Extension Manager Specification

## ADDED Requirements

### Requirement: Preference toggles are bounded and fail with guidance

The `enable-filter`, `disable-filter`, `enable-dns-proxy` and `disable-dns-proxy` subcommands SHALL bound the NetworkExtension preferences round-trip they perform, and SHALL report a failure naming the subcommand, the bound it exceeded, and what the operator can do about it when the round-trip does not complete within that bound. They SHALL NOT wait without limit.

The bound SHALL be long enough for a person to answer a system consent prompt. Saving a configuration the machine has not yet approved raises that prompt and does not return until it is answered, so a bound chosen to fail quickly would abort a supported interactive flow rather than protect it. The bound exists to put a ceiling on an otherwise unbounded wait, not to make the command fail sooner.

Exactly one outcome SHALL be reported. A round-trip that completes as the bound elapses SHALL NOT report both a result and a timeout.

The `activate` subcommand is deliberately NOT bounded: its flow includes waiting for a human to approve a system-extension installation, so waiting is correct there rather than a defect. Because `activate` chains two provider enables in one process, the single-outcome rule above SHALL apply per bounded invocation and SHALL NOT silence the second link of an unbounded chain.

#### Scenario: A stalled round-trip fails within the bound

- **GIVEN** a preference-toggle subcommand whose preferences round-trip never calls its completion handler
- **WHEN** the bound elapses
- **THEN** the subcommand reports a failure naming the subcommand and the bound
- **AND** the failure distinguishes an unanswered consent prompt from an unresponsive preferences daemon, and gives the console-user remedy for the first
- **AND** the subcommand exits non-zero rather than continuing to wait

#### Scenario: A completed round-trip is unaffected

- **GIVEN** a preference-toggle subcommand whose preferences round-trip completes normally
- **WHEN** it reports its result
- **THEN** the result is the one the round-trip produced, and no timeout is reported

#### Scenario: A result at the deadline reports once

- **GIVEN** a preference-toggle subcommand whose round-trip completes at the moment the bound elapses
- **WHEN** both the completion handler and the bound's watchdog attempt to report
- **THEN** exactly one of them reports, and the other is discarded
