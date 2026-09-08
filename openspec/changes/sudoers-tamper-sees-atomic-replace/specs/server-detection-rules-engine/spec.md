# Server detection rules engine

## ADDED Requirements

### Requirement: Sudoers tampering matches the files sudo loads

The `sudoers_tamper` rule SHALL fire when a process creates, writes, or renames into place a file that sudo will parse as policy, and SHALL NOT fire for a path sudo ignores.

`sudoers(5)` defines what sudo parses: `/etc/sudoers` itself, and each file in `/etc/sudoers.d` whose name neither contains a `.` nor ends in `~`. A file sudo skips grants nothing, so an alert on one reports a privilege escalation that cannot have happened. The rule SHALL therefore match `/etc/sudoers` and those direct children of `/etc/sudoers.d/` that sudo will load, in either the bare or the `/private` form.

A rename SHALL be evaluated on its destination, because the destination is what determines whether the file is now policy. A rename whose destination sudo will load SHALL fire regardless of where the source was, since promoting a scratch file into live policy is the escalation whether it came from `/tmp` or from a sibling in the watched directory.

Narrowing the matched paths and observing renames are one change, not two. The narrowing alone would remove a detection that currently works by accident: writes to `<name>.tmp` fire today under the broader pattern, which is the only reason a write-then-rename sequence is caught at all. Removing that without observing the rename would make the sequence silent.

#### Scenario: A drop into a loadable name fires

- **GIVEN** a file event for a path sudo will load, such as `/etc/sudoers` or `/etc/sudoers.d/evil`
- **WHEN** the rule evaluates it
- **THEN** a finding is produced

#### Scenario: A write to a name sudo ignores does not fire

- **GIVEN** a file event for `/etc/sudoers.d/evil.tmp`, whose name contains a `.`
- **WHEN** the rule evaluates it
- **THEN** no finding is produced
- **AND** the same holds for a name ending in `~`, which sudo also skips

#### Scenario: A rename that makes a file loadable fires

- **GIVEN** a `file_rename` event whose source is a path sudo ignores or a path outside the sensitive set
- **AND** whose destination is a name sudo will load
- **WHEN** the rule evaluates it
- **THEN** a finding is produced, reporting the destination as the tampered path

#### Scenario: A rename to a name sudo ignores does not fire

- **GIVEN** a `file_rename` event whose destination is `/etc/sudoers.d/backup.old`, a name sudo skips
- **WHEN** the rule evaluates it
- **THEN** no finding is produced, because the destination is not policy sudo will parse
