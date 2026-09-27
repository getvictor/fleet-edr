## ADDED Requirements

### Requirement: The server pushes default watched paths

The server SHALL send every host a set of default watched paths on top of the operator's set: low-traffic system directories that rules shipped with the product watch. They SHALL be reported with the extension's built-in paths as always watched, SHALL NOT be part of the set an operator edits, and SHALL be sent first in every `set_watched_paths` command, without an operator entry that repeats one.

The server SHALL record, with each version of the set, the default paths that version was stored with. When the stored set carries no defaults or different ones, including a set stored before defaults existed and one never changed at all, the server SHALL store the operator's same paths again as a change by the system principal, audited with a reason, so the version and epoch move forward and hosts apply the new defaults. That SHALL be a no-op once the set carries the current defaults, and servers running at once SHALL together make that change once.

The stored set SHALL remain readable by a server from before default paths existed, since old and new servers share the database during a rolling upgrade: the defaults SHALL be stored as ordinary entries marked as defaults, which such a server reads, and keeps pushing, as ordinary entries. When such a server rewrites the set without the marks, the server SHALL treat the defaults as unrecorded, restore them, and not keep their unmarked repeats among the operator's paths. The limit on a set's encoded size SHALL apply to what a host is sent, the defaults included.

#### Scenario: A deployment that never configured a set pushes the defaults

- **GIVEN** a watched-path set that was never changed
- **WHEN** the server brings the set up to its defaults
- **THEN** the set moves to version 1 as a change by the system, keeping no operator paths
- **AND** every enrolled host is sent the default paths

#### Scenario: A set stored before the defaults keeps its paths and gains them

- **GIVEN** a set stored before default paths existed, holding operator paths
- **WHEN** the server brings the set up to its defaults
- **THEN** the set moves to its next version with the same operator paths
- **AND** hosts are sent the default paths followed by the operator's

#### Scenario: Replicas racing add the defaults once

- **GIVEN** several servers finding the set without the current defaults at once
- **WHEN** each brings the set up to its defaults
- **THEN** the set moves forward by one version and each host is sent it once

#### Scenario: A server from before the defaults still reads the set

- **GIVEN** a set this server stored, with the defaults and an operator path
- **WHEN** a server from before default paths existed reads the column
- **THEN** it decodes the set as a list of paths, the defaults among them

#### Scenario: A set an old server rewrote is restored

- **GIVEN** a set rewritten by a server from before default paths existed, holding the defaults as unmarked entries and an operator path
- **WHEN** the server brings the set up to its defaults
- **THEN** the set moves to its next version with the defaults recorded and only the operator path among the operator's

#### Scenario: The defaults are reported as always watched

- **GIVEN** an operator reading the watched-path set
- **WHEN** the server answers
- **THEN** the paths every host watches whatever the set holds include the default paths as well as the extension's built-in ones

## MODIFIED Requirements

### Requirement: Hosts that miss the watched-path push get the set

The server SHALL periodically queue the current watched-path set, as a `set_watched_paths` command carrying the same `{version, epoch, paths}` the push sends, for every host with an active enrollment whose latest `set_watched_paths` command does not already carry it. A host SHALL be sent the set when it has no such command, when that command carried a different version or epoch than the current set, when it was queued no later than the host's latest enrollment (both times read from the database clock, so skew between the server and the database cannot reorder them), when it expired or was cancelled, or when it failed at least six hours ago.

A pending, acknowledged, or completed command at the current version, queued since the host's latest enrollment, SHALL count as delivered, so a host that is offline is not sent a new copy every time the server checks. A failed command SHALL count as delivered for six hours before the set is queued again, so a host whose agent cannot run the command does not accumulate a failed command every check. A failed command with no recorded completion time SHALL count as delivered rather than being queued again immediately, since nothing says how long ago it failed and retrying on every check is what the six-hour wait exists to prevent.

Before each check the server SHALL bring the stored set up to its default watched paths, as the requirement on default watched paths states, so a deployment that never configured a set is still sent them. While the set has never been changed and the server has no default paths to push, it SHALL queue nothing.

#### Scenario: A failure with no completion time is not retried at once

- **GIVEN** a host whose latest command for the current set failed with no recorded completion time
- **WHEN** the server checks
- **THEN** the set is not queued for it again

#### Scenario: A host enrolled after a change gets the set

- **GIVEN** a watched-path set was changed while a host was not yet enrolled
- **WHEN** the host has enrolled and the server next checks
- **THEN** the current set is queued for that host, carrying the same version and epoch the push carried
- **AND** it is not queued again while that command is pending

#### Scenario: An expired or reinstalled host gets the set again

- **GIVEN** a host whose command for the current set expired undelivered, and a host that took the set and then enrolled again after a reinstall
- **WHEN** the server next checks
- **THEN** the current set is queued for both hosts

#### Scenario: A never-configured deployment is sent the defaults

- **GIVEN** a deployment whose watched-path set was never changed, and a host enrolled in it
- **WHEN** the server next checks
- **THEN** the set is brought up to the default paths and queued for the host, carrying them
