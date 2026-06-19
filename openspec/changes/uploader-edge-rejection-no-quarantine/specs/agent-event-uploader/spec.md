# Agent Event Uploader Specification (delta)

## MODIFIED Requirements

### Requirement: Permanent client errors are not infinitely retained

The system SHALL stop retrying batches that consistently produce an HTTP 400 (bad request) response after the configured maximum and SHALL emit an audit log entry so the operator can investigate why the server rejected those events. HTTP 400 is the only status the ingestion route emits to signal that a batch's content is bad (`invalid_json`, `host_id_mismatch`, `missing_fields_at_<i>`), so it is the only status that consumes the quarantine budget. A 401 (re-enroll) and a 413 (split-and-retry) keep their own recovery paths and do not consume the quarantine budget; any other status is handled as a blanket endpoint rejection (see "Blanket endpoint rejections keep the queue").

#### Scenario: Server consistently returns 4xx for a malformed event

- **GIVEN** the server returns HTTP 400 (the only malformed-content 4xx the ingest route emits) for a batch on every attempt
- **WHEN** the configured maximum retry budget is exhausted
- **THEN** the uploader records an audit log entry identifying the failure
- **AND** the batch is not retransmitted indefinitely

#### Scenario: A poison batch quarantines while sibling batches deliver

- **GIVEN** one batch consistently returns HTTP 400 while other batches return 2xx
- **WHEN** the poison batch crosses the quarantine threshold
- **THEN** only the poison batch is sealed
- **AND** the sibling batches are delivered and marked uploaded

## ADDED Requirements

### Requirement: Blanket endpoint rejections keep the queue

The ingestion route (`POST /api/events`) emits only 200, 400, 413 (intake handler) and 401, 503 (host-token middleware). Any other status the uploader observes (in particular 403, and likewise 404, 405, 408, 429, 451, and other non-2xx 4xx) is therefore not a per-batch content verdict from the EDR server but a blanket rejection injected by an edge/proxy/WAF or a wrong/unhealthy origin. The system MUST treat such a response as a transient endpoint rejection: it SHALL keep the batch queued (neither sealing it nor consuming the quarantine budget), back off to the next drain cycle, and resume delivery automatically when the endpoint returns 2xx. Retention during the rejection window is bounded only by the queue's `EDR_AGENT_QUEUE_MAX_BYTES` lossy cap. The system MUST emit a distinct WARN log and increment a dedicated counter labelled by status code so an operator can distinguish "the endpoint is rejecting every upload" from a quiet success.

#### Scenario: Sustained 403 preserves the queue and resumes on recovery

- **GIVEN** the endpoint returns HTTP 403 for every upload across many drain cycles
- **WHEN** the uploader drains repeatedly
- **THEN** no batch is sealed or dropped and the queued events remain (bounded only by the queue byte cap)
- **AND** the uploader emits the endpoint-rejection WARN and increments the endpoint-rejected counter
- **AND** when the endpoint later returns 2xx, the queued events are delivered and marked uploaded

#### Scenario: A non-400 4xx does not consume the quarantine budget

- **GIVEN** the endpoint returns HTTP 429 (or 404) for a batch on every attempt
- **WHEN** the uploader drains more times than the quarantine threshold
- **THEN** the batch is not sealed and remains queued for a future cycle
