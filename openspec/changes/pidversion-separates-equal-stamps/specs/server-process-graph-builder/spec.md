# server-process-graph-builder delta: equal fork stamps are separated by kernel generation

## ADDED Requirements

### Requirement: Inherited parent path resolves the generation that forked the child

When a fork event carries no parent path of its own, the system resolves it from the parent PID's own record, and SHALL answer with the generation of that PID which was running at the child's fork instant.

Two generations of one PID CAN share a fork timestamp: a stale generation is closed only when a strictly earlier stamp is seen, and the sensor stamps events when it handles them rather than when they occur, so an exact collision is not prevented upstream. Where two records share a stamp AND the image ordering cannot separate them, the system SHALL prefer the one whose kernel generation counter is higher, and SHALL NOT resolve that tie by the order in which the records were ingested. Ingest order is not evidence: a later generation's fork is routinely materialized before an earlier one's, which is why the inherited path was wrong often enough to be worth fixing in the first place.

The qualification is load-bearing rather than hedging. Where the records DO differ in which image was in force at the instant, that difference decides, even if it selects the record with the lower kernel counter. Preferring the counter there would select a chain's newest image regardless of the instant being asked about, which is the re-exec error the image ordering exists to prevent, so the kernel counter is a tie-break within the existing ordering and not an override of it.

Where one record carries a kernel generation and the other does not, and the image ordering again cannot separate them, the system SHALL prefer the one that does, so the outcome follows the available evidence rather than the storage layer's ordering of absent values.

The kernel generation SHALL be consulted only AFTER the image ordering has selected within a generation, never before it. That counter increments on exec as well as on fork, so the records of a single re-exec chain carry ascending values; ranked earlier it would select a chain's newest image regardless of the instant being asked about, which is the re-exec error the image ordering exists to prevent. It therefore decides only between generations that the image ordering cannot separate.

Both implementations of this lookup, the stored query and the in-batch overlay, SHALL order identically. An ordering corrected in one and not the other makes the answer depend on whether a parent happened to be processed in the same batch as its child.

#### Scenario: Two generations sharing a fork timestamp are separated by kernel generation

- **GIVEN** two generations of one PID recorded with the same fork timestamp and neither having exec'd
- **AND** the generation with the LOWER kernel counter was ingested last
- **WHEN** a child's inherited parent path is resolved at an instant after both forks
- **THEN** the path of the generation with the higher kernel counter is returned
- **AND** the answer does not depend on the order the two records were ingested in

#### Scenario: A generation carrying kernel evidence outranks one without

- **GIVEN** two generations of one PID recorded with the same fork timestamp
- **AND** only one of them carries a kernel generation counter
- **WHEN** a child's inherited parent path is resolved
- **THEN** the path of the generation carrying the counter is returned
