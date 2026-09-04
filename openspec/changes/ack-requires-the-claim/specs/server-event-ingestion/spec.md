# Server event ingestion: acknowledgement requires the claim delta

## ADDED Requirements

### Requirement: Acknowledgement requires still holding the claim

The system SHALL acknowledge a claimed batch only while the acknowledging attempt still holds the claim it was given, and SHALL report to that attempt whether it did.

A claim expires and is re-offered, so an attempt that takes longer than its lease runs alongside the attempt that reclaimed its work. An unconditional acknowledgement lets both succeed and tells neither that it lost, which makes the condition undetectable by construction: nothing downstream can distinguish a batch processed once from a batch processed twice, and nothing reports that a lease was exceeded at all.

Work that is not idempotent SHALL be done only by the attempt that still holds the claim. Folding events into the process graph and persisting alerts are both idempotent, by event identity and by alert deduplication respectively, so a replayed batch is harmless there. Anything additive is not, and belongs to whichever attempt holds the claim.

Losing a claim SHALL NOT be reported as an error. It is a normal outcome of a lease being exceeded, and treating it as a failure would make a caller retry work another attempt is already doing.

Losing a claim SHALL be reported to the operator, because it is the only signal that leases are being exceeded.

#### Scenario: An ack from a lost claim does not acknowledge

- **GIVEN** a batch whose claim expired and was re-claimed by another attempt
- **WHEN** the original attempt acknowledges it
- **THEN** the batch is not marked processed
- **AND** the original attempt is told it no longer held the claim, without an error

#### Scenario: An ack from the holding claim acknowledges

- **GIVEN** a batch whose claim is still held by the acknowledging attempt
- **WHEN** it acknowledges
- **THEN** the batch is marked processed
- **AND** the attempt is told it held the claim
