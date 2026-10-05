## ADDED Requirements

### Requirement: A snapshot exec carries the running process's signature

A synthetic `exec` event emitted at startup for a process that already existed SHALL carry the code signature of that process's running code, in the same `code_signing` shape a live exec carries: its signing identifier, its team, the kernel's code-signing flags, and whether it is a platform binary. The signature SHALL be read from the running code rather than the file on disk, which may have been replaced since the process started, and reading it SHALL NOT contact the network.

A process can exit and its pid be reused between listing the process table and reading the signature, so the system SHALL attribute a signature only when the process holding the pid started when the listed one did, and SHALL otherwise emit the event without a signature. An unsigned process SHALL be emitted without a signature, as a live exec of one is.

Without the signature, every judgement made on it fails for any process that predates the extension, which is every process started at boot and every one alive across an agent upgrade: a rule's built-in skip of Apple's indexing services, and an operator's `team_id` or `signing_id` exclusion, so the process is reported instead.

#### Scenario: An Apple daemon carries its signature

- **GIVEN** an Apple platform daemon, such as Spotlight's `mds`, that was running when the extension started
- **WHEN** the extension emits its startup snapshot
- **THEN** the daemon's `exec` event carries its signing identifier, no team, its code-signing flags, and `is_platform_binary = true`

#### Scenario: An unsigned process carries no signature

- **GIVEN** a running process whose code carries no signing identifier
- **WHEN** the extension emits its startup snapshot
- **THEN** that process's `exec` event carries no `code_signing`

#### Scenario: A reused pid gets no signature

- **GIVEN** a process listed in the startup snapshot whose pid is taken by a different process before its signature is read
- **WHEN** the extension reads the signature
- **THEN** the `exec` event carries no `code_signing` rather than the new process's
