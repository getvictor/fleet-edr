# Server event ingestion

## MODIFIED Requirements

### Requirement: A batch that cannot be processed does not stall its host

The system SHALL bound how long a failing batch of queued work is retried. Once a batch's events have both exceeded a bounded number of attempts AND been failing for longer than a bounded period, the system SHALL set those events aside so that the host's remaining work is claimed and processing resumes.

Unbounded retry is not merely wasteful here. The processing path claims a host's queued work in timestamp order, so a batch that fails returns to the front of that order, ahead of everything newer, and a batch that fails DETERMINISTICALLY is retried without end while nothing newer for that host is ever claimed. What stops is not the failing rule or the failing event: the process graph stops advancing for that host and every detection rule stops seeing its activity.

Both bounds SHALL apply, not either. A transient failure can produce a great many attempts in a short window, so an attempt count alone would set aside events that a moment's patience would have processed. A duration alone would set aside a batch that failed once and then waited for an unrelated reason.

Setting events aside SHALL NOT delete them, and SHALL NOT be described as data loss. The queue entry is retained, and separately the event archive is written before the work queue and retained on its own window under the "Durable event archive with bounded retention" requirement, so the event itself remains available for hunting queries and for alert evidence. What is given up depends on the stage the batch was withdrawn at: at the detection stage the event is in the graph already and what is lost is the remainder of detection, while at the process-graph stage its evaluation is lost and its contribution to the graph MAY be, since an earlier attempt may have folded it before a later one failed.

The system SHALL treat the resulting loss as the lesser harm, and the reasoning SHALL be recorded rather than left implicit. Claiming in timestamp order exists so a host's stream is folded in order, and skipping events breaks that for the events skipped when they never reached the graph: a later event whose predecessor was set aside at the graph stage without ever having been folded is itself folded as though the predecessor never arrived, which is a bounded hole in one host's process tree. A batch withdrawn at the detection stage leaves no such hole, and gives up detections on events already in the graph. The alternative to either is that the same host contributes nothing to the graph and raises no detections at all, for as long as the condition lasts.

Setting events aside SHALL be observable, both as a counter that dashboards and alerts can be authored against and as a log record naming the host. A stalled host is otherwise indistinguishable from a quiet one, and the only symptom is an absence of detections that nobody is watching for.

That record SHALL state the consequence that applies to the stage the events were withdrawn at, and SHALL NOT state a consequence that does not. Events can be set aside while the process graph is being built, where they never reach the graph, or during detection, where the batch was already materialised and its process tree is intact. Reporting a process-graph gap for the second sends a responder to inspect healthy data, which is worse than reporting nothing: this record is the only prompt anyone gets, so a prompt that wastes the responder's attention teaches them to discount the next one.

The graph-building stage's consequence SHALL report a POSSIBLE gap rather than a certain one. The bounds that withdraw a batch accrue on its queue entry and count every attempt, whichever stage failed, so a batch can be folded into the graph on one attempt, fail at detection, and be withdrawn later on an attempt whose fold failed. Those events are already in the graph and nothing recorded that they got that far, so the system cannot distinguish that from a batch that never folded at all and SHALL NOT state a certainty it does not have.

The detection stage's consequence SHALL name what was lost rather than which step failed, and SHALL NOT claim the events went unevaluated. A rule's own failure is isolated and does not withdraw the batch at all; two other conditions do, and they are indistinguishable at the withdrawal: a failure to persist an alert, which stops the batch at the finding it happened on so the rules after it never run, and an evaluation that asked to be retried until its bounds ran out, where every rule ran. Naming rule evaluation would be false for the first and would point a responder at rule execution while the failure was in alert storage. For the same reason the consequence SHALL be that alerts those events would have raised MAY be missing rather than that they ARE: alerts written before the failure remain durable, and overstating the loss sends someone hunting for alerts that are already there.

The log MESSAGE SHALL be the same for every stage, with the consequence carried as an attribute. The record is found by searching for that line, and a message that varied by stage would leave any search, and any alert authored on it, matching some withdrawals and not others.

Events set aside SHALL NOT be counted as backlog by the processor-backlog signal that reports how much work is waiting. They are not waiting for anything, so counting them would hold that signal up permanently by a number that never drains, which is the shape an operator reads as a processor falling behind. The separate set-aside counter is what reports them, and any probe that validates the backlog signal SHALL use the same predicate so the two cannot disagree.

Events set aside SHALL age out under the deployment's retention window rather than accumulating in the work queue without bound, and that window SHALL be measured from when the events were WITHDRAWN rather than from when their batch first failed. The two diverge without bound, because attempts accrue only while a host is online: a batch that fails once, waits out an offline stretch longer than the whole retention window, and only then reaches the attempt bound would be withdrawn and swept on the next sweep, leaving no window to inspect it in. The retention window doubles as the period an operator has to look, so it SHALL start when there is something to look at.

#### Scenario: A deterministically failing batch stops blocking its host

- **GIVEN** a host whose oldest queued batch fails every time it is processed, and newer events queued behind it
- **WHEN** the batch has exceeded both the attempt bound and the duration bound
- **THEN** its events are set aside and the newer events are claimed and processed
- **AND** detections resume for that host

#### Scenario: A transient failure is retried rather than set aside

- **GIVEN** a batch that fails repeatedly in quick succession and would then succeed
- **WHEN** it has exceeded the attempt bound but not the duration bound
- **THEN** it is retried rather than set aside
- **AND** it is processed once the condition clears

#### Scenario: Setting events aside is counted and logged

- **GIVEN** a batch whose events are being set aside
- **WHEN** that happens
- **THEN** a counter is incremented by the number of events set aside
- **AND** a log record names the host, so the condition is visible without waiting for someone to notice missing detections

#### Scenario: The record states the consequence for its stage

- **GIVEN** a batch set aside while rules were being evaluated, after its events were folded into the process graph
- **WHEN** the record is read
- **THEN** it reports that detection did not complete for those events, so alerts they would have raised may be missing
- **AND** it does not report a gap in that host's process graph, which would send a responder to inspect an intact process tree
- **AND** it does not name rule evaluation as the step that failed, since the same withdrawal follows a failure to store an alert, in which no rule failed at all
- **AND** a batch set aside while the graph was being built reports a possible gap in that graph instead
- **AND** both carry the same log message, so one search finds either

#### Scenario: Setting an event aside does not delete it

- **GIVEN** an event whose queue entry has been set aside
- **WHEN** the queue is inspected
- **THEN** the entry is still present with its payload intact, withdrawn from processing rather than removed
- **AND** the entry names the event, so which events a host stopped contributing is recoverable

#### Scenario: A set-aside event stops counting as backlog

- **GIVEN** a host with one event set aside and no other queued work
- **WHEN** the processor-backlog signal is read
- **THEN** it reports no waiting work
- **AND** the set-aside entry is still present, reported by the set-aside counter instead

#### Scenario: Events set aside do not accumulate without bound

- **GIVEN** events set aside longer ago than the configured retention window
- **WHEN** the queue's retention sweep runs
- **THEN** those entries are removed
- **AND** entries set aside inside the window are kept

#### Scenario: The retention window starts when events are withdrawn

- **GIVEN** an entry whose batch first failed longer ago than the retention window but which was set aside only moments ago
- **WHEN** the queue's retention sweep runs
- **THEN** the entry is kept, because the window measures how long it has been available to inspect
