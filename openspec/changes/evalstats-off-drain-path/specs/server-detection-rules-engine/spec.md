# Server detection rules engine: evaluation statistics off the drain path delta

## ADDED Requirements

### Requirement: Evaluation statistics are aggregated in process and written periodically

The system SHALL NOT write per-rule evaluation statistics to the database while processing an event batch. Those statistics SHALL be aggregated per replica in memory and written on a periodic flush and on graceful shutdown.

The write is synchronous and every replica contends on the same database instance, so performing it per batch bounded the batches per second a whole deployment could process however many replicas were added. An observability feature SHALL NOT bound the data plane.

The aggregate SHALL be exact with respect to what the per-batch writes would have accumulated: counts and total durations add, and the worst single evaluation takes the larger of the two rather than the more recent.

That exactness covers the COUNTERS. The times a statistics row carries are taken when it is written, so deferring the write attributes work up to one flush interval later than it happened, and work in the final seconds of a day can be recorded against the next one. This is a bounded and accepted difference, not an exactness claim: the interval is seconds against a window read in days, so no decision the numbers exist for turns on it.

A failed flush SHALL retain its statistics and retry them on a later flush, so a transient database failure costs no counts. Because the pending set is keyed by rule, retaining it SHALL NOT grow with the number of failed attempts. The only condition under which statistics are lost is an ungraceful shutdown, and that SHALL be documented where an operator reading the table would look.

Buffering is acceptable for these statistics and SHALL NOT be extended to monitor match counts. A monitor match is a fact about the world that drives a promotion decision, so losing one makes a rule look quieter than it is; an evaluation cost sample is one of thousands and losing a window changes no decision.

Per-rule evaluation duration SHALL additionally be reported as a metrics histogram, so the question of which rule is slow is answerable with percentiles rather than only from the durable table.

#### Scenario: Processing a batch performs no statistics write

- **GIVEN** a replica processing many event batches
- **WHEN** each batch's per-rule statistics are recorded
- **THEN** no statistics are written to the database
- **AND** the recorded work is still held for a later flush

#### Scenario: A flush writes the exact aggregate

- **GIVEN** several batches recorded for the same rule since the last flush
- **WHEN** the flush runs
- **THEN** one row per rule is written whose counts and total duration are the sums, and whose worst single evaluation is the largest of them

#### Scenario: A graceful shutdown writes what it had accumulated

- **GIVEN** a replica holding unflushed statistics
- **WHEN** it is shut down gracefully
- **THEN** the statistics are written before it exits

#### Scenario: A failed flush is retried rather than dropped

- **GIVEN** a replica holding unflushed statistics and a database that rejects the write
- **WHEN** the flush fails and further batches are recorded
- **THEN** a later successful flush writes every count from both the failed attempt and the work recorded after it

#### Scenario: Evaluation duration is available as a histogram per rule

- **GIVEN** a rule evaluated against a batch
- **WHEN** the evaluation completes
- **THEN** its duration is recorded on a metrics histogram attributed to that rule
