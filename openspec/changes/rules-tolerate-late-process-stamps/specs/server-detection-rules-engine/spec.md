# server-detection-rules-engine

## ADDED Requirements

### Requirement: Rules tolerate a process stamped after an event that followed it

A rule that attributes an event to a process SHALL tolerate the process being recorded with a timestamp LATER than an event which must causally have followed it, up to a bounded pad. An outbound connection cannot precede the process that opened it, and a payload cannot precede the shell that ran it, so a small negative delta is evidence of a late stamp rather than evidence of no relationship.

The tolerance SHALL be applied where the two stamp sources meet, which is the comparison between the triggering event and the shell, and MUST NOT be applied to a parent edge. A parent SHALL be resolved at the instant its CHILD forked, because that is the only instant at which the question has an answer. Resolving a parent edge at an unrelated later instant asks which process holds that PID now, and widening such a lookup forward is worse than not tolerating skew at all: a PID reused after the child forked would answer as the child's parent, fabricating an ancestor chain from an unrelated process. A parent edge needs no tolerance in any case, because a child's fork and its parent's fork come from the same event stream and so run late together, preserving their order.

The rule's shell window SHALL apply the tolerance to its LOWER bound only. The upper bound is a real limit on how long after a shell the rule still attributes activity to it and MUST NOT be widened.

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

#### Scenario: A child is not attributed to a generation that recycled its parent's PID

- **GIVEN** a process whose parent exited and whose parent's PID was then reused by an unrelated process, after the child forked
- **WHEN** the engine resolves that child's ancestry while evaluating a later event
- **THEN** the resolved parent is the generation that was alive when the child forked, not the generation that recycled the PID
