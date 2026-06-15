# Server process graph builder: uid/gid range and poison-event isolation delta

## ADDED Requirements

### Requirement: Process records store the full macOS uid and gid range

The system SHALL persist process effective UID and GID values across the entire macOS `uid_t`/`gid_t` range (unsigned 32-bit, 0 through 4294967295), including the conventional `nobody` value (4294967294) and the unset `KAUTH_UID_NONE` sentinel (4294967295). A UID or GID anywhere in that range MUST NOT cause the originating event to be rejected at persistence time.

#### Scenario: A process owned by nobody is materialized

- **GIVEN** an `exec` event whose UID is 4294967294 and GID is 4294967295
- **WHEN** the builder processes the event
- **THEN** the process record persists with UID 4294967294 and GID 4294967295

### Requirement: A single unpersistable event does not stall batch processing

The system SHALL isolate a single event that fails with a permanent (non-retryable) error so that it does not block the rest of its batch or any subsequent batch. A permanent error is one that recurs identically on every retry: a payload that cannot be parsed (a JSON syntax or type error), or a value the database can never store (a data-integrity violation). Such an event MUST be dropped, and logged, while the remaining events in the batch are still materialized and the batch is reported successful so the processor marks it processed rather than re-fetching it. An event that fails with a transient (retryable) error MUST instead cause the batch to be reported as failed so the processor retries it and no data is lost to a recoverable fault.

#### Scenario: A poison event is dropped and the batch advances

- **GIVEN** a batch containing one event that fails with a permanent data error and one valid event
- **WHEN** the builder processes the batch
- **THEN** the valid event's process record is materialized
- **AND** the batch is reported successful so the processor marks it processed and does not retry it
- **AND** the poison event is not stored

#### Scenario: A malformed event is dropped and the batch advances

- **GIVEN** a batch containing one event whose payload cannot be parsed and one valid event
- **WHEN** the builder processes the batch
- **THEN** the valid event's process record is materialized
- **AND** the batch is reported successful so the processor marks it processed and does not retry it
- **AND** the malformed event is not stored

#### Scenario: A transient failure retries the batch

- **GIVEN** an event that fails with a transient, retryable database error
- **WHEN** the builder classifies the failure
- **THEN** the failure is reported as non-permanent so the batch is retried rather than the event being dropped
