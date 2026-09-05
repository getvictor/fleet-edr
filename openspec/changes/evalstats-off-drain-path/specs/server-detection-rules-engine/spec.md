# Server detection rules engine: evaluation statistics off the drain path delta

## ADDED Requirements

### Requirement: Evaluation statistics are aggregated in process and written periodically

The system SHALL NOT write per-rule evaluation statistics to the database while processing an event batch. Those statistics SHALL be aggregated per replica in memory and written on a periodic flush and on graceful shutdown.

The write is synchronous and every replica contends on the same database instance, so performing it per batch bounded the batches per second a whole deployment could process however many replicas were added. An observability feature SHALL NOT bound the data plane.

The aggregate SHALL be exact with respect to what the per-batch writes would have accumulated: counts and total durations add, and the worst single evaluation takes the larger of the two rather than the more recent.

That exactness covers the COUNTERS of any window that is successfully written. The times a statistics row carries are taken when it is written, so deferring the write attributes work up to one flush interval later than it happened, and work in the final seconds of a day can be recorded against the next one. This is a bounded and accepted difference, not an exactness claim: the interval is seconds against a window read in days, so no decision the numbers exist for turns on it.

A failed flush SHALL discard that window rather than retrying it, and the system SHALL report the loss.

Retrying was tried and rejected, and the reason belongs here because it is not obvious. The write is an ADDITIVE upsert, so a retry is at-least-once: a commit whose result never reaches the client is added again, repeated failures are not bounded to one window, and because later work merges in between attempts the derived mean moves rather than staying put. Neither retrying nor discarding yields exact totals once the database is failing, so the choice goes to the one whose behaviour can be stated in a sentence. Making the write idempotent is the only thing that would make it exact under failure, and that is a schema question tracked separately.

Statistics are therefore lost in three conditions, all of which SHALL be documented where an operator reading the table would look: a failed flush, including the final one on shutdown; an ungraceful shutdown; and work recorded after the final flush, since the evaluation workers are not joined to it. Each is bounded by one flush window.

Buffering is acceptable for these statistics and SHALL NOT be extended to monitor match counts. A monitor match is a fact about the world that drives a promotion decision, so losing one makes a rule look quieter than it is; an evaluation cost sample is one of thousands and losing a window changes no decision.

This requirement constrains WHEN the durable record is written and what that costs. It does not weaken the separate observability requirement that the record exists durably per rule and survives the process: a lost window is a gap in a durable record, not a return to reporting from a span.

Per-rule evaluation duration SHALL additionally be reported as a metrics histogram, so the question of which rule is slow is answerable with percentiles rather than only from the durable table. It SHALL measure the same duration the durable table records, INCLUDING time spent reading the process graph: a rule slow through its reads is as much an operator problem as one slow through matching, and two surfaces answering one question with different quantities is worse than either choice. The evaluation budget continues to exclude that time, for the different purpose of not letting a slow datastore disable rules.

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
