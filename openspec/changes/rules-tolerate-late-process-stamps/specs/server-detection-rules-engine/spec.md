# server-detection-rules-engine

## ADDED Requirements

### Requirement: Rules tolerate a process stamped after an event that followed it

A rule that attributes an event to a process SHALL tolerate the process being recorded with a timestamp LATER than an event which must causally have followed it, up to a bounded pad. An outbound connection cannot precede the process that opened it, and a payload cannot precede the shell that ran it, so a small negative delta is evidence of a late stamp rather than evidence of no relationship.

The `suspicious_exec` rule's ancestor resolution SHALL apply this tolerance, trying the exact instant first so a recycled PID still resolves to the correct generation, and widening only a lookup that already missed. The rule's shell window SHALL apply the same tolerance to its LOWER bound only. The upper bound is a real limit on how long after a shell the rule still attributes activity to it and MUST NOT be widened.

The tolerance MUST remain bounded. A shell whose recorded exec is far beyond the pad after the trigger is not a late stamp, and attributing the trigger to it would make the rule's window meaningless.

This exists because an agent that stamps events when its handler finishes, rather than from the kernel's own event time, records a process exec after the network connection that process opened. Stamping from kernel time removes the cause at the source, but hosts run older agents until they upgrade and some handler latency always remains.

#### Scenario: A shell is recorded as exec'ing after the connection it opened

- **GIVEN** a non-shell parent spawns a shell whose recorded exec time falls after the outbound connection made from beneath it, by less than the tolerated pad
- **WHEN** the engine evaluates the batch
- **THEN** the engine resolves the shell and produces a `suspicious_exec` finding naming it
- **AND** the finding is produced without widening the window's upper bound

#### Scenario: A shell far beyond the pad is still rejected

- **GIVEN** a shell whose recorded exec time falls after the trigger by far more than the tolerated pad
- **WHEN** the engine evaluates the batch
- **THEN** the engine produces no finding, because that separation is not a late stamp
