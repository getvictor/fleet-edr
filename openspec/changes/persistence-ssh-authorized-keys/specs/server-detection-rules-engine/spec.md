## ADDED Requirements

### Requirement: SSH authorized keys changes are reported

The server SHALL include `~/.ssh/authorized_keys` and `~/.ssh/authorized_keys2` in the default watched paths every host is sent. The `persistence_ssh_authorized_keys` rule SHALL fire on a write-mode `open` of, or a `file_rename` onto, a path ending in `/.ssh/authorized_keys` or `/.ssh/authorized_keys2`, naming the process that wrote it and linking the finding to that process. It SHALL NOT fire on any other file, including a copy of a key file under another name. An exclusion for the rule SHALL suppress it by a path glob on the writer's path.

#### Scenario: A key file written in any home fires

- **GIVEN** a write-mode open of `authorized_keys` in a person's home, in root's home in its `/private` spelling, and of `authorized_keys2`
- **WHEN** detection evaluates each event
- **THEN** `persistence_ssh_authorized_keys` raises a medium-severity finding naming the writer and the file

#### Scenario: A key file renamed into place fires

- **GIVEN** a rename whose destination is a user's `~/.ssh/authorized_keys`
- **WHEN** detection evaluates the event
- **THEN** the rule raises a finding saying a file was renamed onto the key file

#### Scenario: Another file does not fire

- **GIVEN** writes to `~/.ssh/known_hosts`, to `~/.ssh/authorized_keys.bak`, and to an `authorized_keys` outside `.ssh`
- **WHEN** detection evaluates the events
- **THEN** no finding is raised

#### Scenario: A writer is waived by its path

- **GIVEN** an exclusion for `persistence_ssh_authorized_keys` with a path glob matching the writer
- **WHEN** detection evaluates the writer's change to a key file
- **THEN** no finding is raised
- **AND** the same glob saved for another rule does not suppress it
