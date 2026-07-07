## MODIFIED Requirements

### Requirement: Process-termination command

The system SHALL execute a kill-process command by terminating the requested process identifier on the local host using the platform's native process-termination primitive (SIGKILL on Unix-like platforms, TerminateProcess on Windows) and SHALL report a structured outcome distinguishing success from "no such process" and from permission denied.

The change from the prior requirement is that termination is specified in terms of the platform's native primitive rather than SIGKILL only, so a Windows agent terminates via TerminateProcess; the reported-outcome contract and the Unix behavior are unchanged.

#### Scenario: Successful kill

- **GIVEN** a kill-process command is received with a live process identifier
- **WHEN** the agent terminates that process identifier
- **THEN** the executor reports completed with a result identifying the killed process identifier

#### Scenario: Process is already gone

- **GIVEN** a kill-process command is received but the process has already exited
- **WHEN** the agent attempts to terminate it
- **THEN** the executor reports failed with an error reason that conveys "no such process"

#### Scenario: Process identifier is non-positive

- **GIVEN** a kill-process command is received with a zero or negative process identifier
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed without sending any signal to the kernel
- **AND** the failure reason identifies the invalid input
