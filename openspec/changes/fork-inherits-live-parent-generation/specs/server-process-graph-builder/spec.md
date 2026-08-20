# server-process-graph-builder delta: a fork inherits the path of the newest parent generation that had forked by then

## MODIFIED Requirements

### Requirement: Fork creates a process record

The system SHALL create a new process record on receipt of a `fork` event. The record MUST capture the host, the new PID, the parent PID, and the fork timestamp.

A fork-without-exec child has no image of its own, so the system SHALL give it the parent's image path. That path MUST be resolved as of the fork's OWN timestamp: the system MUST select the newest generation of the parent PID that had forked at or before that instant. Resolving by parent PID alone MUST NOT be done, because PIDs are reused and a fork is routinely materialized after its parent's PID has been recycled, so the newest generation of that PID at materialization time is not in general the one that forked the child. A generation that forked AFTER the child cannot be the child's parent, and that is the whole of the constraint. The resolution MUST be identical whether the batch is applied as a set or event by event, since the batched path is the production one.

The system MUST NOT additionally require the parent generation to be recorded as still alive at the fork's timestamp. A parent is alive when its child forks, by construction, so an aliveness test can never correct the answer here; it can only discard the sole candidate on the strength of an exit timestamp, and those timestamps are the least reliable data the record holds. The extension stamps events at handler time, and the PID-reuse sweep SYNTHESIZES an exit at the recycling fork's timestamp, so a record stating that a parent exited before its own child forked is a record that is wrong rather than a parent that is disqualified. Requiring aliveness was measured on 154,660 never-exec'd rows: it blanked the inherited path on 29,880 of them while correcting 3,413 FEWER than the fork bound alone, a roughly 4:1 net loss of information. A parent generation with no observed exit MUST likewise still supply the path, so that a host whose exit events are late, reordered, or dropped does not stop inheriting paths.

The record MUST carry no inherited path when, and only when, no generation of the parent PID had forked yet at the child's fork timestamp. An absent path states that the parent's image is unknown, which is the honest answer where no candidate exists; asserting an image the parent could not have been running is not, because the process tree, the process detail view, and every detection rule that gates on the process path then read it as fact.

#### Scenario: A daemon forks a worker

- **GIVEN** a `fork` event carrying child PID and parent PID
- **WHEN** the builder applies the event
- **THEN** a process record exists for the host and child PID with the parent PID and fork timestamp set
- **AND** the record has no exec metadata and no exit metadata yet

#### Scenario: A fork arrives after its parent's PID was recycled

- **GIVEN** two generations of one parent PID, an earlier one that ran a known image, and a later one that recycled the PID and runs a different image
- **WHEN** a `fork` event stamped before the later generation forked is applied after both generations are already recorded
- **THEN** the child record carries the earlier generation's image path
- **AND** it does not carry the recycling generation's image path
- **AND** a `fork` stamped at or after the later generation's fork carries the later generation's path instead
- **AND** the result is the same whether the earlier generation ended at an observed exit or was closed by the PID-reuse sweep

#### Scenario: A parent whose exit was never observed still supplies the path

- **GIVEN** a parent generation that ran a known image and whose exit event never arrived
- **WHEN** a `fork` event naming it as parent is applied
- **THEN** the child record carries that generation's image path

#### Scenario: A parent recorded as exited before its child forked still resolves

- **GIVEN** a parent PID whose newest recorded generation ran a known image and carries an exit timestamp earlier than a later instant
- **WHEN** a `fork` event stamped at that later instant naming that PID as parent is applied
- **THEN** the child record carries that generation's image path
- **AND** the recorded exit does not disqualify it, since a parent cannot fork after it dies and the exit record is therefore the unreliable half

#### Scenario: No generation of the parent PID had forked yet

- **GIVEN** a parent PID whose every recorded generation forked after a given instant
- **WHEN** a `fork` event stamped at that instant naming that PID as parent is applied
- **THEN** the child record carries no inherited path
- **AND** it does not carry the path of a generation that did not yet exist
