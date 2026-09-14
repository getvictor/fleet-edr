## MODIFIED Requirements

### Requirement: Sensitive-path file-modification capture

The system SHALL emit a write-mode `open` event when a process creates or writes a file under the sensitive target set, carrying the writing process PID, the file path, and write-mode access flags. The sensitive target set is the built-in paths (`/etc/sudoers` and anything under `/etc/sudoers.d/`) together with the watched-path set the server last pushed. The system SHALL NOT forward a broad stream of file opens: collection is scoped at the source to the sensitive target set via a dedicated Endpoint Security client with inverted target-path muting, kept separate from the process-authorization client so the scoping never affects exec authorization (ADR-0008). Writes to paths outside the sensitive set MUST NOT be collected.

The system SHALL additionally emit a `file_rename` event when a process renames a file into, within, or out of that same sensitive set, carrying the renaming process PID, the source path, and the destination path. Both paths are required: a rename is the only operation in this set that makes a file become sudo policy without any write to the destination, and the source is what distinguishes a file promoted from a scratch path elsewhere from one already inside the watched directory.

Renames SHALL be collected under the same inverted target-path muting as creations and writes, which matches a rename when EITHER of its paths falls in the sensitive set.

#### Scenario: A write to a sensitive path is captured

- **GIVEN** the extension is running with the sensitive-path file-modification client active
- **WHEN** a process writes to `/etc/sudoers` (or a direct child of `/etc/sudoers.d/`)
- **THEN** a write-mode `open` event is emitted carrying the writing process PID, the file path, and the write-mode access flags
- **AND** the event reaches the server and is available to the detection pipeline

#### Scenario: A rename event carries both of its paths

- **GIVEN** a rename touching the sensitive set has been observed
- **WHEN** the extension serializes it
- **THEN** the `file_rename` event carries the renaming process PID, the source path, and the destination path
- **AND** the destination is carried under the same field name every other file event uses for its target, so one detection can read both

Note on verification: this scenario pins the event's SHAPE, which is what the extension's unit tests can reach. That the ESF client is subscribed and that `handleRename` reads both halves of the rename union are exercised at the system / VM layer per `docs/testing-strategy.md`, because `FileTamperSubscriber` imports EndpointSecurity and is outside the unit-testable target.

## ADDED Requirements

### Requirement: The watched-path set is pushed by the server

The system extension SHALL accept a watched-path set from the server, delivered by the agent, and SHALL make it part of the sensitive target set on the running file-tamper client without a restart. A set is a `version`, an optional `epoch` (the set's server update time in Unix microseconds), and a list of `paths` entries, each an absolute `path` and a `match` of `literal` (exactly that file) or `prefix` (every path starting with it).

The extension SHALL apply a set only when it is ahead of the last set it accepted, ordered by `epoch` and then by `version`, and SHALL otherwise leave the active and persisted sets unchanged. Commands can reach the host out of order, so without this an older set delivered late would replace a newer one. The server forces each set's `epoch` past the one in its database, so `epoch` orders every set it issues across a step back in the database clock, and across a server database restore that sends `version` backwards once the clock is past the epochs issued before the restore; a restore whose database clock is still behind them delays new sets until it passes them, as ordering on either axis did; `version` breaks a tie, which is what orders sets from a server that sends no `epoch`; every server that pushes this set sends one. A set issued before a restore, still on its way to the host when a set is saved since, is therefore older and is not applied, even though its `version` is higher. This is the rule application control uses for its policy snapshots, and the two SHALL keep one rule.

The built-in paths SHALL stay watched whatever set is pushed: a pushed set adds to them and cannot remove them, because the shipped sudoers detections depend on them. An empty pushed set SHALL therefore leave exactly the built-in paths watched.

Replacing the set SHALL NOT stop observing a path that both the previous and the new set cover. A path under a firmlinked root (`/etc`, `/tmp`, `/var`) SHALL be watched in both its `/private` and its root-linked spelling, since Endpoint Security reports the resolved form.

The extension SHALL persist a set before applying it and SHALL start from the persisted set, so a restarted extension watches the pushed paths before the agent next delivers a set. A set that cannot be persisted SHALL NOT be applied, so the running set and the one a restart loads never differ; a later delivery of the same set tries again.

An entry with a `match` the extension does not know SHALL be skipped while the rest of the set is applied, so an older extension keeps watching what it understands when a newer server adds a kind of entry. So SHALL any entry the server's rules for an entry refuse, which the extension holds again rather than relying on the server to have held them, because what reaches the kernel is a C string: a path that is not absolute, is longer than 1023 bytes in its `/private` spelling (`PATH_MAX` less the C string's terminating NUL), contains an ASCII control character (NUL included), or has an empty, `.` or `..` segment; a `literal` ending in `/`; and a `prefix` not ending in `/` or not lying below a top-level directory (judged through `/private` for `/etc`, `/tmp` and `/var`). A top-level prefix, however it is spelled, would put every write under that tree on the wire. A payload that is not a watched-path document at all SHALL leave the watched set, and the persisted one, unchanged.

A pushed path that the client cannot mute SHALL be logged rather than end the extension, since the set persists and ending the extension would restart it into the same failure. When any mute in an update fails, the running client SHALL NOT unmute anything that update drops, and the failed path is attempted again by the next update. That retention holds for the running process only: a restarted extension watches the persisted set.

Note on verification: decoding, the combination with the built-in paths, the mute difference between two sets, and persistence are pinned by the extension's unit tests. That the running client observes an added path and stops observing a dropped one is exercised at the system / VM layer per `docs/testing-strategy.md`, because `FileTamperSubscriber` imports EndpointSecurity and is outside the unit-testable target.

#### Scenario: A pushed set is applied without a restart

- **GIVEN** the file-tamper client is running and watching a pushed set
- **WHEN** a new set arrives that adds one path and drops another
- **THEN** the client starts observing the added path and stops observing the dropped one
- **AND** paths in both sets are not unmuted at any point, and the extension does not restart

#### Scenario: A set that cannot be persisted is not applied

- **GIVEN** the extension cannot write its persisted set
- **WHEN** a set that supersedes the current one arrives
- **THEN** the set is not applied, the current set stays in force, and a later delivery of the same set is still treated as new

#### Scenario: An older set delivered late does not replace a newer one

- **GIVEN** the extension has accepted a set at a given version and epoch
- **WHEN** a set arrives that is behind on both version and epoch, or is the same set again
- **THEN** the active set and the persisted set are unchanged
- **AND** a set whose version is behind but whose epoch is ahead, as after a server database restore, is applied

#### Scenario: A pre-restore set is refused

- **GIVEN** the extension has accepted a set saved after a server database restore, whose version is lower than before the restore
- **WHEN** a set issued before the restore arrives, with a higher version and an earlier epoch
- **THEN** the active set and the persisted set are unchanged

#### Scenario: A prefix at the top of the filesystem is not watched

- **GIVEN** a pushed set containing a `prefix` entry for `/`, a top-level directory such as `/Users/`, `/private/etc/`, or a path that only reads as deeper through a NUL or `..` segments
- **WHEN** the extension decodes it
- **THEN** those entries are skipped and counted, and the remaining entries are applied

#### Scenario: The built-in paths stay watched whatever is pushed

- **GIVEN** any pushed set, including an empty one
- **WHEN** the client applies it
- **THEN** `/etc/sudoers` and `/etc/sudoers.d/` are watched in both spellings, exactly as before the set was configurable

#### Scenario: A pushed set survives an extension restart

- **GIVEN** a set has been pushed and applied
- **WHEN** the extension restarts
- **THEN** it loads the persisted set and watches those paths from its first event, before the agent delivers a set again

#### Scenario: An entry the extension does not understand is skipped

- **GIVEN** a pushed set containing an entry with an unknown `match`, or a path that is not absolute
- **WHEN** the extension decodes it
- **THEN** that entry is skipped and counted, and the remaining entries are applied

#### Scenario: A malformed push leaves the watched set unchanged

- **GIVEN** a watched set is active
- **WHEN** a push arrives whose payload is not a watched-path document
- **THEN** the active set and the persisted set are unchanged
