# Agent XPC Receiver: throttle dropped-event warnings delta

## MODIFIED Requirements

### Requirement: Events flow into the queue without blocking the receiver

The receiver SHALL deliver received events into a downstream channel without blocking on the channel. If the downstream buffer is full the receiver MAY drop the affected event but MUST surface the loss via a warning so operators can detect the condition, and MUST keep reading subsequent events from the XPC connection. To avoid flooding the log when a slow consumer sustains a backlog, the receiver SHALL rate-limit the warning per affected service: it MUST emit a warning on the first drop after a quiet period so the onset is visible promptly, then MAY suppress further warnings for that service within a bounded interval, folding the suppressed drops into the next emitted warning. Each emitted warning MUST identify the affected service and MUST carry the count of dropped events it accounts for, so an operator sees the magnitude of loss without one log line per dropped event. Each service's rate-limit window is independent.

#### Scenario: Downstream consumer falls behind

- **GIVEN** the receiver is delivering events into a buffered channel
- **WHEN** the consumer is too slow and the channel fills up
- **THEN** the receiver drops the event that could not be enqueued
- **AND** the receiver logs a warning identifying the affected service and the count of dropped events
- **AND** the receiver continues reading subsequent events

#### Scenario: Sustained drops are coalesced into a throttled summary

- **GIVEN** the receiver has already warned about a full channel for a service
- **WHEN** further events for that service are dropped within the rate-limit interval
- **THEN** the receiver does not emit a warning per dropped event
- **AND** once the interval elapses the next drop emits a single warning carrying the count of events dropped since the previous warning
- **AND** a drop on a different service emits its own warning independently of the first service's interval
