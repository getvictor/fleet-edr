# Server event ingestion

## ADDED Requirements

### Requirement: The queue carries a value across retry attempts

When work is returned to the queue after a failed attempt, the caller MAY hand over opaque bytes that it has resolved about that batch, and the queue SHALL keep them with those events and give them back to whoever WITHDRAWS the batch from processing.

This exists because the attempt that resolves something about a batch is, by construction, the attempt that then failed, and the attempt that ends the batch's life may be a later one that never got far enough to resolve anything. Retry bounds accrue on the queue entry and count every attempt, whichever stage failed, so a batch can be evaluated on one attempt and withdrawn on an attempt that failed a stage before evaluation. Without somewhere for the value to sit between them, the batch's last word says nothing about what earlier attempts found, and the loss falls on precisely the hosts that had processing trouble.

The queue SHALL NOT interpret the bytes. What they mean belongs to the caller's own context, and a queue that understood them would be that context's concern living in this one.

A return that hands over NO bytes SHALL leave whatever is kept for those events alone rather than clearing it. That case is the whole point: an attempt that failed before it resolved anything must not erase what an earlier attempt resolved.

The bytes SHALL be returned ONLY to a withdrawal of EXACTLY the set of events they were supplied for. A kept value can outlive that set, because which events form a batch is decided per attempt and can change between them, and a value covering an event that some other batch has since accounted for would account for it twice. An implementation SHALL therefore record which events a value was supplied for and compare, and SHALL return nothing when the set has moved. That loses the value rather than attributing it to events that did not produce it, which is the direction this whole mechanism errs in.

The bytes SHALL be returned ONLY when the batch is withdrawn in full, and SHALL NOT be returned to an attempt whose events go back on the queue. A batch that is coming back is processed again and resolves its own, so handing the value out before the batch's last word would count it twice. A partial withdrawal leaves events that are claimed and processed again while the value covers all of them, which is the same double count.

The queue SHALL state a bound on how large a value it will carry, and a caller SHALL hand over none rather than one over it. The storage is finite and refuses an oversized write rather than truncating it, and a refused write fails the return itself, which leaves the batch in flight until its claim expires. Returning the batch is what the call is for and the value is incidental to it, so the cost of an oversized value falls on the value.

Keeping the value SHALL NOT cost a write the return does not already make, and SHALL NOT require state held in a replica. Per-replica state would be lost on exactly the restarts that produce the failures this exists to survive, and the app tier is multi-replica by design.

#### Scenario: A value survives the attempt that supplied it

- **GIVEN** a batch whose first attempt hands over a value and is returned to the queue
- **WHEN** a later attempt hands over nothing and withdraws every one of those events
- **THEN** the withdrawing attempt is given the first attempt's value
- **AND** it was not cleared by the intervening return that supplied none

#### Scenario: A batch that is coming back is given nothing

- **GIVEN** a batch whose attempt hands over a value and whose events have not passed their retry bounds
- **WHEN** the events are returned to the queue
- **THEN** no value is given back to that attempt
- **AND** none is given back on a withdrawal of only part of the batch

#### Scenario: A later value replaces the one it supersedes

- **GIVEN** a batch that has already had a value kept for it
- **WHEN** a later attempt hands over a different value and is returned to the queue
- **THEN** the batch's withdrawal is given the later value
- **AND** not both of them

#### Scenario: An oversized value is dropped rather than failing

- **GIVEN** an attempt whose value is larger than the bound the queue states
- **WHEN** the attempt returns its batch to the queue
- **THEN** the batch is returned and its attempt is counted as any other
- **AND** no value is carried for it

#### Scenario: A value is withheld from a batch it was not supplied for

- **GIVEN** a value supplied for one set of events, and a later attempt whose set of events differs
- **WHEN** that later attempt withdraws its events in full
- **THEN** it is given no value
- **AND** the events it shares with the original set are not accounted for twice
