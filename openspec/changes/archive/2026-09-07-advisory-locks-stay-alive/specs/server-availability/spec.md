# server-availability delta: an advisory lock stays held for as long as its holder runs

## ADDED Requirements

### Requirement: An advisory lock is held for as long as its holder runs

Every advisory lock this system takes SHALL remain held for the whole time its holder is running, regardless of how long that is, and SHALL NOT depend on a database server setting to stay held.

The hazard is specific to how these locks are used. The lock is pinned to one connection while the work runs on a different pooled connection, so for the entire critical section the lock's own connection is idle by construction. Anything that closes an idle connection, a `wait_timeout` an operator tuned down, a proxy, a failover, an administrative kill, frees the lock without the holder being told. The system SHALL therefore keep the lock's connection active for as long as the lock is held, rather than requiring critical sections to be short enough to finish inside whatever the server's idle timeout happens to be.

Losing a lock SHALL NOT be silent. The failure mode this exists to remove is a holder that keeps running after its lock is gone, completes, and reports success: the work looks like it ran under mutual exclusion when for part of its life it did not, and for the per-host event claim that means two claimers folding one host's stream concurrently. So when a lock is lost while its holder runs, the system SHALL cancel the holder's context and SHALL report the loss to the caller as a distinct, inspectable failure rather than an ordinary error, so a caller that needs exclusivity can retry. A holder that fails on its own terms SHALL keep reporting its own error, which is the more specific diagnosis.

Where a lock is handed out without a callback, and so has no context to cancel, the system SHALL still keep it alive and SHALL record the loss, and that form SHALL document that it cannot abort its caller.

#### Scenario: A lock outlives the closing of its idle connection

- **GIVEN** a caller holding an advisory lock while its work runs on a different connection
- **AND** a critical section longer than the database's idle-connection timeout
- **WHEN** the work runs to completion
- **THEN** the lock is still held throughout, because its connection was kept active
- **AND** no other caller enters the section in the meantime

#### Scenario: A lock lost mid-callback is reported, not absorbed

- **GIVEN** a caller running under an advisory lock
- **WHEN** the connection holding that lock is killed while the callback is still running
- **THEN** the callback's context is cancelled
- **AND** the caller is told the lock was lost, distinguishably from failing to acquire it in the first place
- **AND** a callback that returned no error of its own is not reported as a success

#### Scenario: The callback's own failure is not masked by the lock loss

- **GIVEN** a callback that both loses its lock and fails on its own terms
- **WHEN** it returns
- **THEN** the caller sees the callback's own error rather than the lock-loss report
