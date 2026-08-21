# server-availability delta: the candidate-host hint reads a bounded window

## ADDED Requirements

### Requirement: The candidate-host hint costs the same whatever the backlog

The processor asks the queue which hosts have claimable work before claiming any of them. That hint SHALL be answerable at a cost that does not grow with the depth of the queue, because a hint whose cost scales with the backlog is most expensive exactly when the pipeline is furthest behind, and it is re-asked every poll interval by every worker.

The hint SHALL therefore read its candidates through an index, in timestamp order, rather than scanning and sorting the queue. Splitting the claimable predicate into one arm per claim state is what makes that possible: expressed as a single disjunction across states it cannot use an index, because no index is ordered by timestamp across claim states.

The hint MAY read only a bounded number of the oldest claimable events, and is therefore APPROXIMATE: a host whose oldest claimable event falls outside that bound need not be offered in that cycle. This is permitted because the hint carries no exclusivity guarantee and a claim validates its own preconditions. The bound SHALL be a fixed compiled constant rather than an operator knob.

Whatever bound is used, the events it admits SHALL be the oldest ones, so that the globally oldest claimable event in the queue is always among the candidates considered. This is what makes the approximation safe rather than a starvation bug: a host is passed over only when the bound is filled with work strictly older than anything that host has, which is the work that should be processed first regardless. A host omitted for this reason SHALL be offered once the older work ahead of it drains, so the omission is a deferral bounded by the queue rather than a host being held back.

The hint SHALL NOT drop the in-flight floor when it bounds its reads. Omitting an eligible host costs one idle worker for one cycle; offering a blocked one costs the fleet a full claim lease, because a blocked host sorts to the front of the candidate window on the longest-waiting ordering and stays there. The two errors are not symmetric and the cheap direction is the one the bound is allowed to take.

#### Scenario: The oldest host is offered however deep the queue is

- **GIVEN** one host owning more than a full candidate window of queued events
- **AND** another host owning a single event older than all of them
- **WHEN** the processor asks for candidate hosts
- **THEN** the host with the older event is offered
- **AND** it sorts ahead of the host with the larger backlog

#### Scenario: A host beyond the window is deferred rather than lost

- **GIVEN** one host owning a full candidate window of the oldest queued events
- **AND** another host whose only event is newer than all of them
- **WHEN** the processor asks for candidate hosts
- **THEN** only the host holding the older work is offered
- **WHEN** that older work is claimed and acknowledged
- **AND** the processor asks again
- **THEN** the deferred host is offered
