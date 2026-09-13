## ADDED Requirements

### Requirement: Watched file paths are configured over the API

The server SHALL hold one watched-path set: a version and a list of entries, each an absolute `path` and a `match` of `literal` or `prefix`, which every host's file-tamper client watches on top of its built-in paths. Version 0 SHALL be the empty set.

`GET /api/v1/detection-config/watched-paths` SHALL return the set, the built-in paths every host watches regardless of it, and the maximum number of entries, to a caller permitted `detection_config.read`.

`PUT /api/v1/detection-config/watched-paths` SHALL replace the set, for a caller permitted `detection_config.write`, only when the request carries a non-blank reason and the proposed set is valid. A replacement SHALL be stored as the next version, SHALL queue a `set_watched_paths` command carrying `{version, epoch, paths}` for every enrolled host, where `epoch` is the set's update time in Unix microseconds so hosts keep ordering sets after a database restore sends `version` backwards, and SHALL be audited with the reason, the previous and new sets, and the number of hosts the command was queued for and missed. A command that could not be queued for some hosts SHALL NOT fail the replacement, which is already stored; the response SHALL report both counts.

The server is the only place the set is validated, so it SHALL refuse a proposed set, storing nothing and queueing nothing, when it has more than 32 entries, or any entry whose path is not absolute, has an empty, `.` or `..` segment, is longer than 1024 bytes, or contains a control character, whose `match` is neither `literal` nor `prefix`, that is a `literal` ending in `/`, that is a `prefix` not ending in `/`, that is a `prefix` naming a top-level directory, or that repeats another entry. A path under `/private/etc`, `/private/tmp`, or `/private/var` SHALL be judged by its root-linked form. The refusal SHALL name the entry and the reason.

A top-level prefix is refused because its cost is not bounded by the set's size: every write under a tree such as `/Users/` would reach the wire.

#### Scenario: An operator reads the watched-path set

- **GIVEN** a caller permitted `detection_config.read`
- **WHEN** they request the watched-path set
- **THEN** the response carries the version, the entries, the built-in paths, and the maximum number of entries

#### Scenario: An operator replaces the watched-path set with a reason

- **GIVEN** a caller permitted `detection_config.write` and three enrolled hosts
- **WHEN** they replace the set with a valid list of entries and a reason
- **THEN** the set is stored as the next version with those entries
- **AND** a `set_watched_paths` command carrying that version, the set's update time as its epoch, and those entries is queued for each of the three hosts
- **AND** the change is audited with the reason, the previous and new sets, and the host counts

#### Scenario: A set the server would not watch is refused

- **GIVEN** a proposed set with an entry the rules above refuse
- **WHEN** a caller permitted `detection_config.write` submits it with a reason
- **THEN** the request is refused with a message naming the entry and why
- **AND** the stored set is unchanged and no command is queued

#### Scenario: A change without a reason is refused

- **GIVEN** a caller permitted `detection_config.write`
- **WHEN** they submit a valid set with a blank reason
- **THEN** the request is refused, the stored set is unchanged, and no command is queued

#### Scenario: Reading and changing the set need their permissions

- **GIVEN** a caller not permitted `detection_config.read`, and one permitted to read but not `detection_config.write`
- **WHEN** the first requests the set and the second submits a replacement
- **THEN** both are refused as forbidden, and the stored set is unchanged

#### Scenario: A push that misses hosts does not undo the change

- **GIVEN** a valid replacement whose commands cannot be queued for the enrolled hosts
- **WHEN** a caller permitted `detection_config.write` submits it with a reason
- **THEN** the set is stored as the next version
- **AND** the response and the audit row report how many hosts the command was not queued for
