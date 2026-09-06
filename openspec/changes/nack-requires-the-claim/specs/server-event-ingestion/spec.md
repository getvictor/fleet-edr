# Server event ingestion: returning a batch requires the claim too

## MODIFIED Requirements

### Requirement: Acknowledgement requires still holding the claim

The system SHALL acknowledge a claimed batch only while the acknowledging attempt still holds the claim it was given, and SHALL report to that attempt whether it did.

Returning a batch to the queue SHALL require the same. An attempt that no longer holds a claim SHALL NOT return its events, count an attempt against them, or withdraw them from processing, and SHALL be told it withdrew nothing, which is true. Identifying a claim by an event's STATE rather than by the claim it was issued for is not the same question: a superseded attempt then resets a claim the replacement holds, which makes the replacement's own acknowledgement fail so its work is redone, and counts a failure the replacement did not have against a bound that lives on the event and ends in the event being withdrawn.

Where an attempt names events it holds ALONGSIDE events it does not, every effect SHALL be confined to the events it holds. Checking ownership and then acting on what was asked for leaves the same defect in a narrower window, which is what a batch looks like after a lease expires under part of it.

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

#### Scenario: A nack from a lost claim withdraws nothing

- **GIVEN** an event whose claim expired and was re-claimed by another attempt
- **WHEN** the original attempt returns it to the queue
- **THEN** the event is left claimed by the attempt that holds it
- **AND** no attempt is counted against it
- **AND** the original attempt is told nothing was withdrawn, without an error
- **AND** the holding attempt can still acknowledge it

#### Scenario: A nack acts only on the events its claim holds

- **GIVEN** an attempt returning events of which it holds some and not others
- **AND** one of the events it does not hold has already reached the bounds that withdraw it
- **WHEN** it returns them
- **THEN** only the events it holds are returned to the queue
- **AND** the event at its bounds is not withdrawn, because this attempt never held it

