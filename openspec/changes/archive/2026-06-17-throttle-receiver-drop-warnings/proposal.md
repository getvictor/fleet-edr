# Throttle the receiver's dropped-event warnings

## Why

When a downstream consumer falls behind, the receiver's full-channel drop path (`agent/receiver/common.go`, `tryDeliverEvent`) logs one `receiver event channel full` warning per dropped event. The XPC onEvent callback fires this on every drop, so a slow consumer produces thousands of identical lines in microseconds (observed: 5 lines within ~130µs in a captured `fleet-edr-agent.log`). The flood drowns out every other log line, inflates the OTLP log volume the agent ships, and tells an operator nothing more than the first line already did. The current spec mandates a warning per drop, so the volume is contract, not an accident.

## What changes

- **The drop warning is rate-limited per service and carries a count.** Instead of one log line per dropped event, the receiver emits the warning immediately on the first drop after a quiet period (so the onset is visible promptly), then suppresses further warnings for that service within a fixed interval and folds the suppressed drops into the next summary. Each emitted warning carries a `dropped` count of the events it accounts for, so an operator still sees the magnitude of loss without the flood. Each service name (system extension, network extension) tracks its own window.

### Not in this change

- A lossless OTel counter metric for receiver drops (e.g. `edr.agent.receiver.events_dropped`). The agent already exports queue/uploader drop counters via the OTLP pipeline (ADR-0006), and a receiver-drop metric is the right long-term home for the exact magnitude; this change keeps scope to the log flood and leaves the metric as a follow-up.
- Any change to the drop policy itself: events are still dropped (not buffered or back-pressured), and the receiver still keeps reading subsequent events. Only the warning's volume changes.
