# Detection rules engine: process-optional provenance correlation delta

## ADDED Requirements

### Requirement: Process-optional alert provenance correlation

For an alert that is not attributed to a single process (a process-optional finding such as a LaunchDaemon registration, persisted with `process_id = 0`), the system SHALL, when serving the alert detail, attempt to correlate the alert to the processes genuinely related to the detected artifact and return them as a set of related processes, each tagged with its role. Correlation MUST be performed at read time (alert-detail compose), MUST NOT alter the alert's persisted `process_id` or dedup identity, and MUST degrade gracefully to an empty set when no correlation is found.

For a LaunchDaemon/LaunchAgent registration finding the system SHALL derive related processes from the finding's linked registration event by:

- correlating the registered plist path to the nearest-preceding write-mode `open` event on that path for the same host, resolving the writing PID to a process and tagging it `artifact_writer`; and
- correlating the registered executable path to that executable's own process runs on the host, tagging them `persisted_executable`.

#### Scenario: Writer is correlated to a LaunchDaemon registration

- **GIVEN** a process-optional `privilege_launchd_plist_write` alert whose plist path was written by an observed process captured as a write-mode `open` event
- **WHEN** the operator requests the alert detail
- **THEN** the response includes the writing process among the related processes tagged `artifact_writer`

#### Scenario: No provenance is available

- **GIVEN** a process-optional alert whose plist was not captured as a write-mode `open` event (for example an atomic-rename write) and whose registered executable has no observed process run
- **WHEN** the operator requests the alert detail
- **THEN** the response returns an empty related-process set rather than an error
- **AND** the alert's persisted `process_id` remains zero
