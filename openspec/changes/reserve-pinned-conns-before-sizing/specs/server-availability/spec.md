# server-availability delta: worker sizing subtracts connections that are already pinned

## ADDED Requirements

### Requirement: Worker sizing counts only connections that can actually be obtained

When the system sizes its worker fleet against the database connection pool, it SHALL first subtract every connection that is held for the lifetime of the process and therefore never returned to the pool. Today those are the leader-gated periodic sweeps, each of which pins one connection for its advisory lock from boot to shutdown.

Counting a permanently pinned connection as available is not a rounding error, it is the same stall the sizing check exists to prevent: the fleet is sized against connections that are never coming back, so workers pin what is left for their locks and then wait forever for a claim connection that no one will release. The result is a pipeline that boots cleanly and processes nothing.

The reserved count SHALL be supplied by whatever wires those long-lived holders, not assumed by the component doing the sizing, so that adding or removing a sweep cannot leave the sizing silently wrong.

Only holders that are actually running SHALL be counted. A sweep that is switched off returns immediately when it is given the lock, so its connection is taken and released in brief bursts rather than held; counting it would make the sizing pessimistic and could refuse a pool that is in fact adequate, which is the opposite of the failure this exists to prevent.

Where the remaining budget cannot serve even one worker, the system SHALL refuse to start rather than reduce the fleet, and the threshold it enforces SHALL be the threshold its error reports, including the reservation. A guard that admits a value its own message calls insufficient is worse than no guard: it produces a running deployment whose configuration was already diagnosed as unusable. Once the refusal is honest, the system SHALL NOT floor the computed worker count to a minimum of one, because the refusal already guarantees one is affordable and a floor could only ever manufacture a worker the pool cannot serve.

#### Scenario: A pool with room for the sweeps but not for a worker is refused

- **GIVEN** a connection pool large enough for the leader-gated sweeps but with too little left for one worker
- **WHEN** the processor is constructed with a coordinator
- **THEN** construction fails rather than starting a worker that would stall on its first claim
- **AND** the error names the pool size the deployment needs, counting the reservation

#### Scenario: A budget the guard's own advice rejects is refused rather than reduced

- **GIVEN** a connection budget smaller than the threshold the refusal message tells operators to reach
- **WHEN** the processor is constructed with a coordinator
- **THEN** construction fails
- **AND** the fleet is not silently reduced to a worker that cannot make progress

#### Scenario: Reserving the long-lived holders does not shrink a healthy deployment

- **GIVEN** the shipped connection pool, the shipped worker count, and the leader-gated sweeps reserved
- **WHEN** the processor is constructed
- **THEN** the configured worker count is honored in full
- **AND** no reduction is reported
