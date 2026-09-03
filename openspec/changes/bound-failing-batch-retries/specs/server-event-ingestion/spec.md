# Server event ingestion

## ADDED Requirements

### Requirement: A batch that cannot be processed does not stall its host

The system SHALL bound how long a failing batch of queued work is retried. Once a batch's events have both exceeded a bounded number of attempts AND been failing for longer than a bounded period, the system SHALL set those events aside so that the host's remaining work is claimed and processing resumes.

Unbounded retry is not merely wasteful here. The processing path claims a host's queued work in timestamp order, so a batch that fails returns to the front of that order, ahead of everything newer, and a batch that fails DETERMINISTICALLY is retried without end while nothing newer for that host is ever claimed. What stops is not the failing rule or the failing event: the process graph stops advancing for that host and every detection rule stops seeing its activity.

Both bounds SHALL apply, not either. A transient failure can produce a great many attempts in a short window, so an attempt count alone would set aside events that a moment's patience would have processed. A duration alone would set aside a batch that failed once and then waited for an unrelated reason.

Setting events aside SHALL NOT delete them, and SHALL NOT be described as data loss. The queue entry is retained, and separately the event archive is written before the work queue and retained on its own window under the "Durable event archive with bounded retention" requirement, so the event itself remains available for hunting queries and for alert evidence. What is given up is that event's contribution to the process graph and its evaluation by detection rules.

The system SHALL treat the resulting gap as the lesser harm, and the reasoning SHALL be recorded rather than left implicit. Claiming in timestamp order exists so a host's stream is folded in order, and skipping events breaks that for the events skipped: a later event whose predecessor was set aside is folded as though the predecessor never arrived. That is a bounded hole in one host's process tree. The alternative is that the same host contributes nothing to the graph and raises no detections at all, for as long as the condition lasts.

Setting events aside SHALL be observable, both as a counter that dashboards and alerts can be authored against and as a log record naming the host. A stalled host is otherwise indistinguishable from a quiet one, and the only symptom is an absence of detections that nobody is watching for.

Events set aside SHALL age out under the deployment's retention window rather than accumulating in the work queue without bound.

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

#### Scenario: Setting an event aside does not delete it

- **GIVEN** an event whose queue entry has been set aside
- **WHEN** the queue is inspected
- **THEN** the entry is still present with its payload intact, withdrawn from processing rather than removed
- **AND** the entry names the event, so which events a host stopped contributing is recoverable

#### Scenario: Events set aside do not accumulate without bound

- **GIVEN** events set aside longer ago than the configured retention window
- **WHEN** the queue's retention sweep runs
- **THEN** those entries are removed
- **AND** entries set aside inside the window are kept
