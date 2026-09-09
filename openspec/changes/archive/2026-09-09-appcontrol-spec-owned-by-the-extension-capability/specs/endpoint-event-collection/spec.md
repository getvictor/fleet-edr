# Endpoint event collection

## MODIFIED Requirements

### Requirement: Process lifecycle event capture

The system SHALL emit a `fork` event when a monitored process forks, an `exec` event when a process replaces its image, and an `exit` event when a process exits. Each event MUST carry the originating PID and any additional fields documented for that event type. The `exec` event SHALL additionally carry the process's own kernel PID generation and the `fork` event SHALL carry the child process's kernel PID generation (`pidversion`, read from the respective process's audit token) when it is available, so the server can disambiguate reused PIDs by identity rather than by time. The `pidversion` field is optional: when the audit token is unavailable the event is still emitted without it.

The `exec` event SHALL carry `cdhash`, the code-directory hash of the new image, when the process runs under Apple's Hardened Runtime AND the kernel reported a hash for it. It SHALL omit the field otherwise, in both of the cases that reach that outcome: a process not running under the Hardened Runtime, and a hardened process whose reported hash is all zeros.

Both omissions are deliberate. The kernel maps pages lazily on a non-hardened process and does not re-verify them after load, so the hash reported at exec is not a reliable identity for the bytes that will eventually execute. An all-zero hash is the kernel saying it has none, and emitting it would let a rule whose identifier is forty zeros match by coincidence. A value that cannot be relied on is worse than an absent one.

The field is what lets an operator exclude a code-signed parent from a `suspicious_exec` finding by its non-spoofable code identity instead of a path glob an attacker who can write to a world-writable directory could land inside, so its absence where a hash does exist is a loss of that defence and not a cosmetic gap.

#### Scenario: A user runs a shell command

- **GIVEN** the endpoint event capture is running
- **WHEN** a user launches `/bin/ls` from a shell
- **THEN** the system emits an `exec` event whose payload includes the new image path, the argument vector, the parent PID, the effective UID and GID, and the code-signing identity (team ID, signing ID, platform-binary flag) when the binary is signed
- **AND** the payload includes the process's `pidversion` when its audit token is available
- **AND** the system later emits an `exit` event for the same PID with the process exit status

#### Scenario: A daemon forks a worker

- **GIVEN** the endpoint event capture is running
- **WHEN** a process calls `fork(2)` without a subsequent exec
- **THEN** the system emits a `fork` event whose payload identifies the parent PID and the child PID
- **AND** the payload includes the child process's `pidversion` when its audit token is available

#### Scenario: The exec event carries cdhash only when the kernel reported one

- **GIVEN** the endpoint event capture is running
- **WHEN** a process execs a binary that runs under Apple's Hardened Runtime and the kernel reports a hash for it
- **THEN** the `exec` event payload carries `cdhash`
- **AND** an exec of a binary that does not use the Hardened Runtime omits `cdhash`
- **AND** an exec whose reported hash is all zeros omits `cdhash` rather than carrying forty zeros
- **AND** the event is otherwise well-formed in every case

## REMOVED Requirements

### Requirement: Process exec authorization

**Reason**: The requirement still describes the singleton blocklist that application control replaced: it says the system evaluates every exec "against the active blocklist" and denies when "the target binary path is on the blocklist". Three archived changes rewrote it and the archive applied none of them, so the canonical text is the pre-application-control design. There is no blocklist today; there is a typed policy snapshot walked in a fixed precedence order across six rule types, with enforcement levels, a deadline budget for a synchronous hash, and an operator-selected fallback posture when that budget is exhausted.

Rewriting it in place would re-create the duplicate that caused the drift, because every clause it would carry is already canonical elsewhere. `extension-application-control` owns the decision through `Precedence walk`, `AUTH_EXEC denial on BLOCK match`, `Deadline-guarded synchronous SHA-256 for BINARY rule consultation`, and `Deadline fallback posture`; the first of those states that a `BLOCK` / `PROTECT` match is denied so the new image does not run, and that any other outcome is allowed. `Process lifecycle event capture` in this capability owns the other half, that an exec emits an `exec` event. Nothing this requirement says is lost by removing it.

**Migration**: None. This is a documentation reconciliation of shipped behaviour, and the decision it describes is unchanged. Its two scenarios carried markers on two `ApplicationControlStore` tests that assert rules route into their own typed maps, which is not what either scenario describes; both test comments concede the gap in prose. Those markers move to a new `Snapshot persistence format is typed` scenario that states what the tests actually pin. The denial and allow behaviours keep the coverage they already had under `extension-application-control/auth-exec-denial-on-block-match`.
