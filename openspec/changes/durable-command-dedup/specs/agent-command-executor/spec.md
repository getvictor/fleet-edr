## ADDED Requirements

### Requirement: Command execution is deduplicated durably across transports and restarts

The agent SHALL key command execution on a durable, per-agent ledger so a command's side effect runs at most once across BOTH the push (control connection) and poll transports and across agent restarts. Before running a command's side effect the agent SHALL record a write-ahead claim for the command id; after the side effect it SHALL record the terminal outcome. On encountering a command id that the ledger already records, the agent SHALL NOT re-run the side effect: if a terminal outcome is recorded it re-reports that outcome, and if only a write-ahead claim is recorded (a prior attempt that did not complete, for example an interrupted process) it reports the command failed rather than re-running the side effect, so a non-idempotent command such as `kill_process` never signals a since-reused PID on re-delivery.

#### Scenario: A command executed on one transport is not re-executed by the other

- **GIVEN** a command whose side effect the agent has already run and recorded a terminal outcome for (over the control connection)
- **WHEN** the same command id is delivered again on the poll path after the connection drops
- **THEN** the agent does not run the side effect again
- **AND** it re-reports the recorded terminal outcome, so the command's status stays stable rather than flipping

#### Scenario: A recorded outcome survives an agent restart

- **GIVEN** a command whose terminal outcome the agent recorded before it stopped
- **WHEN** the agent restarts and the same command id is delivered again
- **THEN** the recorded outcome is still available from the durable ledger
- **AND** the agent re-reports it without re-running the side effect
