# Endpoint event collection

## MODIFIED Requirements

### Requirement: Sensitive-path file-modification capture

The system SHALL emit a write-mode `open` event when a process creates or writes a file under a fixed set of sensitive target paths (currently `/etc/sudoers` and any direct child of `/etc/sudoers.d/`), carrying the writing process PID, the file path, and write-mode access flags. The system SHALL NOT forward a broad stream of file opens: collection is scoped at the source to those sensitive target paths via a dedicated Endpoint Security client with inverted target-path muting, kept separate from the process-authorization client so the scoping never affects exec authorization (ADR-0008). Writes to paths outside the sensitive set MUST NOT be collected.

The system SHALL additionally emit a `file_rename` event when a process renames a file into, within, or out of that same sensitive set, carrying the renaming process PID, the source path, and the destination path. Both paths are required: a rename is the only operation in this set that makes a file become sudo policy without any write to the destination, and the source is what distinguishes a file promoted from a scratch path elsewhere from one already inside the watched directory.

Renames SHALL be collected under the same inverted target-path muting as creations and writes, which matches a rename when EITHER of its paths falls in the sensitive set.

#### Scenario: A write to a sensitive path is captured

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process writes to `/etc/sudoers` (or a direct child of `/etc/sudoers.d/`)
- **THEN** a write-mode `open` event is emitted carrying the writing process PID, the file path, and the write-mode access flags
- **AND** the event reaches the server and is available to the detection pipeline

#### Scenario: A rename onto a sensitive path carries both paths

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process renames a file from outside the sensitive set onto a path inside it
- **THEN** a `file_rename` event is emitted carrying the renaming process PID, the source path, and the destination path
- **AND** the event reaches the server and is available to the detection pipeline
