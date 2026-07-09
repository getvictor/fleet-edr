# Agent command executor: pin kill_process to the target process generation

## MODIFIED Requirements

### Requirement: Process-termination command

The system SHALL execute a kill-process command by terminating the requested process identifier on the local host using the platform's native process-termination primitive (SIGKILL on Unix-like platforms, TerminateProcess on Windows) and SHALL report a structured outcome distinguishing success from "no such process" and from permission denied.

The kill-process command MAY carry the kernel process generation (`pidversion`) the operator selected. When it does AND the agent tracks the target process identifier's current live generation, the agent SHALL refuse the termination and report a structured failure, sending no signal to the kernel, if the tracked generation differs from the one carried on the command (the process identifier was reused or re-exec'd between selection and execution). When the command carries no generation, or the agent does not track that process identifier's generation (never observed, already exited, or lost across an agent restart), the agent SHALL proceed with the pid-only termination. The generation check therefore only ever strengthens the pid-only behavior: it never refuses a termination that would otherwise have succeeded.

The agent's knowledge of a process identifier's live generation is derived from the endpoint event stream (exec and fork establish a generation, exit clears it); it is a per-replica in-memory cache that is safe to lose, so a cold or lossy cache degrades to pid-only termination rather than blocking.

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

#### Scenario: Kill is refused when the target generation no longer matches

- **GIVEN** a kill-process command carrying a process identifier and a selected generation
- **AND** the agent tracks that process identifier at a different live generation (the identifier was reused or re-exec'd)
- **WHEN** the executor evaluates the command
- **THEN** the executor reports failed with a reason identifying a process-generation mismatch
- **AND** no signal is sent to the kernel

#### Scenario: Kill proceeds when the selected generation still matches

- **GIVEN** a kill-process command carrying a process identifier and a selected generation
- **AND** the agent tracks that process identifier at the same live generation
- **WHEN** the executor evaluates the command
- **THEN** the agent terminates the process identifier and reports completed

#### Scenario: Kill falls back to pid-only when the generation is unsupplied or untracked

- **GIVEN** a kill-process command whose payload carries no generation, or whose process identifier the agent does not currently track
- **WHEN** the executor evaluates the command
- **THEN** the agent terminates the process identifier by identifier alone, as it did before generation pinning
