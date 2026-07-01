## ADDED Requirements

### Requirement: Sibling aggregation collapses repeated leaf execs

The system SHALL provide a read-time transform over the per-host process forest that collapses repeated identical child executions under the same parent into a single aggregated node, so that a parent that spawned N childless children of the same binary identity renders as one node carrying a count rather than N nodes. Two children have the same binary identity when they share the same image path AND the same content hash AND the same code-directory hash. The aggregated node MUST carry the group's total count, the split of that count into exited and running members (a running member has no observed exit), and the earliest and latest fork times in the group. The transform MUST be order-preserving and lossless: it MUST NOT drop or duplicate any process, the total number of underlying processes MUST be preserved (the sum of every aggregated node's count plus one per individual node equals the input leaf count at each level), and the output siblings MUST be deterministically ordered by first fork time. Only childless siblings are eligible to fold; a child that has its own subtree MUST remain an individual node so its descendants are never silently removed. A group smaller than the aggregation threshold MUST remain individual nodes rather than becoming a count-of-one aggregate. Aggregation MUST be opt-outable so a caller can obtain the raw, un-aggregated forest.

#### Scenario: Aggregation preserves every leaf and its order

- **GIVEN** a parent with an arbitrary batch of childless children of varying image paths, binary identities, fork times, and exit states
- **WHEN** the forest is aggregated
- **THEN** the sum of every aggregated node's count plus one for each individual node equals the number of input children
- **AND** no underlying process is dropped, duplicated, or moved to a group of a different binary identity
- **AND** the output siblings are ordered by first fork time
- **AND** each aggregated node's exited and running counts sum to its total count and its first fork time is no later than its last

#### Scenario: N identical-path children collapse into one node

- **GIVEN** a parent that spawned several childless children sharing one image path and binary identity, some exited and some still running
- **WHEN** the forest is aggregated
- **THEN** those children are represented by a single aggregated node carrying the group count, the exited-versus-running split, and the earliest and latest fork times

#### Scenario: A child with its own subtree is never folded away

- **GIVEN** a parent whose children include both repeated childless execs and a child that itself has descendants
- **WHEN** the forest is aggregated
- **THEN** the childless repeats collapse into an aggregated node
- **AND** the child that has descendants remains an individual node with its subtree intact, whose own repeated children may aggregate one level down

#### Scenario: Same path but different binary is not merged

- **GIVEN** two childless children under one parent that share an image path but differ in content hash
- **WHEN** the forest is aggregated
- **THEN** they remain two separate nodes rather than one aggregated node
