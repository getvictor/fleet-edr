# Endpoint event collection: launchd file-tamper coverage delta

## MODIFIED Requirements

### Requirement: Sensitive-path file-modification capture

The system SHALL emit a write-mode `open` event when a process creates or writes a file under a fixed set of sensitive target paths (currently `/etc/sudoers` and any direct child of `/etc/sudoers.d/`, and any file under the system LaunchDaemon/LaunchAgent directories `/Library/LaunchDaemons/` and `/Library/LaunchAgents/` and the per-user `~/Library/LaunchAgents/` directory of the active console user), carrying the writing process PID, the file path, and write-mode access flags. The system SHALL NOT forward a broad stream of file opens: collection is scoped at the source to those sensitive target paths via a dedicated Endpoint Security client with inverted target-path muting, kept separate from the process-authorization client so the scoping never affects exec authorization (ADR-0008). Writes to paths outside the sensitive set MUST NOT be collected.

#### Scenario: A write to a sensitive path is captured

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process writes to `/etc/sudoers` (or a direct child of `/etc/sudoers.d/`)
- **THEN** a write-mode `open` event is emitted carrying the writing process PID, the file path, and the write-mode access flags
- **AND** the event reaches the server and is available to the detection pipeline

#### Scenario: A LaunchDaemon plist write is captured for provenance

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process writes a plist under `/Library/LaunchDaemons/` or `/Library/LaunchAgents/`
- **THEN** a write-mode `open` event is emitted carrying the writing process PID, the plist path, and the write-mode access flags
- **AND** the event reaches the server so the detection pipeline can correlate the writer to the LaunchDaemon registration
