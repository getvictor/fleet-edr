# Observability instrumentation

## MODIFIED Requirements

### Requirement: Monitor-mode matches are recorded durably per rule

The system SHALL record, durably and per rule, how many times each rule matched in monitor mode, so that an operator deciding whether to promote a rule has the rule's observed behaviour in the product rather than only in a metrics backend.

A monitor match SHALL be attributed to the host it matched on and to the day it was recorded, so the record answers both questions a promotion turns on: how often the rule fires, and across how much of the fleet. Those are different decisions. A rule matching many times on one host is a candidate for an exclusion, while the same volume spread across every host means the rule itself is too broad, and a fleet-wide total alone cannot distinguish them.

Counts SHALL be recorded on the transition that ends the batch's life, not while the batch is evaluated. A batch that fails is nacked and replayed whole, so a count written during evaluation is written again by every retry.

Usually that transition is the acknowledgement. The other is the batch being withdrawn from processing for good once its retry bounds are passed, and there the MOST RECENT matches resolved for that batch by any of its attempts SHALL be recorded rather than discarded, because there is no later attempt to record them. Discarding them under-reports for precisely the hosts that had processing trouble, and the figure is what an operator reads when deciding whether to promote a monitor-mode rule, so the bias is toward believing a rule is quiet.

Across attempts, and not merely on the withdrawing one. Processing has stages and the retry bounds do not distinguish them: they accrue on the queue entry and count every attempt, whichever stage failed, so a batch can be evaluated on one attempt and withdrawn on an attempt that failed at the fold and evaluated nothing. Without carrying, the batch's last word says nothing about what it matched.

An attempt that resolved NO matches SHALL NOT displace what an earlier attempt resolved, and this is the case that decides what "most recent" means. Evaluation reports what it accumulated UP TO its failure, so an attempt that fails on an earlier rule than its predecessor reports fewer matches and one that fails on the first reports none. An empty result from a failing attempt is therefore an absence of information and MUST NOT be read as an assertion that the batch matched nothing; reading it that way would discard a predecessor's real matches on the commonest failure there is, which is the under-reporting this requirement exists to prevent.

The residual is stated rather than implied away: where a rule is taken out of monitor mode between two attempts, the carried matches are the demoted rule's and the figure is high by one batch for it. That is accepted because the alternative is systematic. The two cases are indistinguishable at this layer, since evaluation reports an empty result for both, and the recorded figure is already documented as approximate. Telling them apart needs evidence the result does not carry, which is tracked separately.

The matches SHALL survive the attempt that resolved them by riding with the queued events rather than in the replica that evaluated them. Per-replica state would be lost on exactly the restarts that produce these failures, and the app tier is multi-replica by design. The queue SHALL keep them without interpreting them, since a work queue that understood a monitor match would be a detection concern living in it, and keeping them SHALL NOT cost a write the return of a failed batch does not already make.

Only a batch withdrawn IN FULL SHALL be counted this way. The withdrawal decision is made per queued event, so a partly withdrawn batch leaves events that are claimed and evaluated again while the recorded figure covers all of them, and recording it would count the remainder twice. Exactly-once SHALL rest on the queue reporting a withdrawal to one caller rather than on coordination between workers, and withdrawal SHALL be a state an event does not leave. An event that has been withdrawn is not returned to the queue, so no later attempt can withdraw it again and no later attempt is told that it did.

A partial withdrawal therefore loses whatever the withdrawn events alone had matched, and this SHALL be documented rather than implied away. The surviving events are evaluated again and their matches are counted then, but a match that only the withdrawn events produced has no later attempt to produce it. Recording the survivors' share instead would need the figure to carry which event each match came from, which it does not: it is aggregated per rule and host for the batch. Discarding the whole attempt is the choice that cannot over-count, and over-counting is the direction that makes a noisy rule look worse than it is rather than safer than it is.

Two residual inaccuracies remain besides those two, and SHALL be documented rather than implied away. A crash between the transition and the record loses those counts, and so does a recording failure, which is dropped rather than allowed to fail a batch already finished with the queue (below). Which of the two sinks is left ahead depends on where in that window the failure lands: the observability counter is advanced before the durable write, so a crash before that point loses both, and only a crash after it, or a failure of the write itself, leaves the counter ahead of the durable record. That is the direction that carries risk, not the one that avoids it: a rule whose recorded volume is too low looks quiet, which is what persuades an operator to promote it, and promoting a noisy rule is the alert flood monitor mode exists to prevent. It is accepted because the alternative, counting during evaluation, is systematically wrong on every retry rather than rarely wrong in the window between two adjacent statements. A third once stood here, an evaluation outliving its claim lease and being counted by both itself and its replacement, and no longer applies: acknowledgement is conditional on still holding the claim and the loser records nothing. The recorded figure is therefore approximate, and MUST NOT be presented as an exact count of what promoting a rule would produce.

A failure to record SHALL NOT fail the batch. By the time the record is attempted the batch has reached a state it will not be processed again from, whether acknowledged or withdrawn, so there is nothing left to fail; replaying real detection work, or undoing a withdrawal, to save a counter would trade the more valuable thing for the less valuable one.

Recorded counts SHALL be subject to the deployment's data-retention window, and pruning them SHALL NOT require a leader-elected task. The delete is idempotent and needs no coordination, whereas every leader-gated loop holds a database connection for the lifetime of the process and the event processor sizes itself against what those loops leave behind.

#### Scenario: A monitor match is counted once for a batch that is retried

- **GIVEN** a rule in monitor mode that matches events in a batch
- **WHEN** the batch fails and is nacked, and the replayed batch then succeeds and is acknowledged
- **THEN** the rule's recorded match count reflects the batch once, not once per attempt

#### Scenario: Counts are attributed to the rule and the host

- **GIVEN** a rule in monitor mode that matches on two different hosts
- **WHEN** the batches are evaluated and acknowledged
- **THEN** the record distinguishes the two hosts for that rule
- **AND** the per-rule total is the sum across them

#### Scenario: A recording failure does not fail the batch

- **GIVEN** an acknowledged batch whose monitor matches cannot be persisted
- **WHEN** the recording fails
- **THEN** the failure is logged
- **AND** the batch is not nacked and its events are not replayed

#### Scenario: Counts older than the retention window are pruned

- **GIVEN** recorded counts older than the configured retention window
- **WHEN** the prune runs
- **THEN** those counts are deleted
- **AND** counts inside the window are kept

#### Scenario: A withdrawn batch is counted once, not lost

- **GIVEN** a rule in monitor mode that matched events in a batch that then failed
- **WHEN** the batch exhausts its retry bounds and every one of its events is withdrawn from processing
- **THEN** the matches that attempt resolved are recorded
- **AND** they are recorded once, because no later attempt will evaluate those events

#### Scenario: A partly withdrawn batch is not counted yet

- **GIVEN** a failing batch in which only some events have passed their retry bounds
- **WHEN** those events are withdrawn and the rest return to the queue
- **THEN** nothing is recorded for that attempt
- **AND** the events that returned are counted by the attempt that finishes them

#### Scenario: An empty result does not displace earlier matches

- **GIVEN** a batch whose first attempt resolved matches and failed, and a later attempt that reached evaluation but failed before resolving any
- **WHEN** that later attempt withdraws every one of its events
- **THEN** the first attempt's matches are recorded
- **AND** the later attempt's empty result is not read as the batch having matched nothing

#### Scenario: An earlier attempt's matches reach the withdrawal

- **GIVEN** a batch that evaluated and failed on one attempt, and on a later attempt failed before evaluation was reached
- **WHEN** that later attempt withdraws every one of its events
- **THEN** the earlier attempt's matches are recorded, because no attempt will evaluate those events again
- **AND** they are recorded once, by the attempt that withdrew the batch
