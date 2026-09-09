# Server detection rules engine

## MODIFIED Requirements

### Requirement: Portability is derived from the rule rather than declared

The system SHALL derive a rule's kind and portability from the rule itself: whether it carries a detection block, whether the fields that block reads come from Sigma's own taxonomy or are computed by this engine, and whether the event types it consumes can be expressed as one Sigma logsource.

The system SHALL report a rule reading only taxonomy fields as portable to any Sigma-compatible engine, one reading a computed field as valid Sigma that needs fields only this engine supplies, and one with no detection block as not portable at all. Each rule file SHALL state the reason, so a reader of one file in isolation learns why it will or will not run elsewhere.

A rule may also be unportable for a reason that has nothing to do with its fields. Sigma permits exactly one logsource category per rule, so a rule consuming event types that map to different categories cannot be expressed as one Sigma rule: an engine routing by category would deliver the declared category's events and silently never deliver the rest. The system SHALL NOT report such a rule as portable to any Sigma-compatible engine even when every field it reads is taxonomy-standard, and SHALL name the categories that would not be routed, because the failure is silent partial coverage rather than an error.

A rule with no detection block SHALL remain not portable at all whatever its event types, since there is nothing in the file to route events to.

Portability is a promise made to whoever reads the file about whether they can run the rule, so it is derived rather than asserted by hand.

#### Scenario: Portability is derived from the rule rather than declared

- **GIVEN** a rule whose detection block reads a field this engine computes
- **WHEN** its file is generated
- **THEN** the file reports it as valid Sigma requiring fields only this engine supplies, and explains why

#### Scenario: Two Sigma categories are not portable

- **GIVEN** a rule whose detection block reads only taxonomy fields
- **AND** whose event types map to more than one Sigma logsource category
- **WHEN** its file is generated
- **THEN** the file does not report it as portable to any Sigma-compatible engine
- **AND** it names the category another engine would not route events from

#### Scenario: A Go rule stays unportable

- **GIVEN** a rule with no detection block whose event types map to more than one Sigma category
- **WHEN** its file is generated
- **THEN** the file still reports it as not portable at all, rather than as a rule needing fields this engine supplies

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
