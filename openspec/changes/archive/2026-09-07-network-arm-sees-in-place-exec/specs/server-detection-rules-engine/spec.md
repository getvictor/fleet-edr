# server-detection-rules-engine

## ADDED Requirements

### Requirement: Network arm resolves a shell that exec'd its payload in place

The `suspicious_exec` rule's outbound-network arm SHALL resolve its shell ancestor from the connecting PID's own exec chain when the PPID chain yields no shell the arm can fire on, in addition to the existing PPID walk. A shell that executes its payload without forking replaces its own image at the same PID, which closes the shell generation and removes it from the connecting process's ancestry, so an arm that consults only the PPID chain cannot see it. The exec arm already resolves this shape through the same chain.

The fall-through to the chain MUST trigger when the PPID walk produces no shell the arm can fire on, not only when it produces no shell at all. Where a shell exec'd in place, the walk does not terminate empty: it returns the next shell above, typically the interactive login shell, whose own exec is far older than the rule's window. A condition that reached the chain only on an empty walk would therefore never reach it in the case the chain exists to serve.

A shell resolved from the exec chain SHALL be subject to the same gates as one resolved from the PPID chain: the trigger event must fall within the shell's window, the shell's non-shell parent must not match an operator exclusion, and a shell already reported in the batch must not be reported twice. The chain is a second place to look for the shell, never a relaxation of when the rule fires.

#### Scenario: A shell execs its payload in place and the payload connects out

- **GIVEN** a non-shell parent spawns a shell that replaces its own image with the payload at the same PID, with an interactive login shell far above it in the PPID chain whose exec is outside the rule's window
- **WHEN** the payload makes an outbound connection and the engine evaluates the batch
- **THEN** the engine produces a `suspicious_exec` finding naming the shell that ran the payload and the non-shell parent above it
- **AND** the finding links to the connecting process, so an analyst opening the alert lands on the payload rather than on the shell

#### Scenario: The shell on the exec chain is outside the window

- **GIVEN** a shell that exec'd its payload in place, whose own exec is older than the rule's window at the time of the outbound connection
- **WHEN** the engine evaluates the batch
- **THEN** the engine produces no finding, because consulting the exec chain does not relax the window

#### Scenario: A re-exec with no shell on the chain does not fire

- **GIVEN** a non-shell process that replaced its image with another non-shell binary at the same PID, which then connects out
- **WHEN** the engine evaluates the batch
- **THEN** the engine produces no finding, because the arm looks for a shell on the chain rather than for the presence of a re-exec
