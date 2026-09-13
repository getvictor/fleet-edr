## ADDED Requirements

### Requirement: Monitor records are written per batch

The monitor records a batch of events produces SHALL be written together when the batch's evaluation ends, not one transaction per finding, with one event-archive read for all of their triggering events. Each record SHALL carry the same row, deduplication, event links and evidence it would carry if written alone, and SHALL enqueue no webhook delivery. The records SHALL be written whether the batch's evaluation succeeds or ends in an error, so a batch that is not processed again still keeps what it found. A failure to write them SHALL fail the batch without hiding the batch's own error.

#### Scenario: A batch's monitor records are written together

- **GIVEN** a batch in which several monitor-mode findings from more than one rule match
- **WHEN** the batch is evaluated
- **THEN** all of its monitor records are written in one store call, in the order they were found
- **AND** each record has its event links and the evidence the archive holds, an event shared by two records included

#### Scenario: A failed batch keeps the monitor records it found

- **GIVEN** a batch in which a monitor-mode finding matches before another rule fails, either retryably or not
- **WHEN** the batch's evaluation ends in that failure
- **THEN** the monitor record is still written, and the batch's own error still reaches the processor
