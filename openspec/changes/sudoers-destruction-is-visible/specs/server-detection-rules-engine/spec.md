# Server detection rules engine

## ADDED Requirements

### Requirement: Destroyed sudo policy is detected separately from tampering

The system SHALL detect destruction of sudo policy: a file sudo will parse being emptied or removed. It SHALL report that separately from the rule covering a sudoers file being written or renamed into place.

The separation is required rather than stylistic. Writing sudo policy is an escalation, and the rule covering it maps to the ATT&CK technique for abusing elevation control. Destroying it grants nothing: it removes access, and it removes whatever record was written. Reporting destruction under the escalation technique would place it on a coverage page under a heading that misdescribes what happened, so the two SHALL carry different technique mappings.

Destruction SHALL be detected only for files sudo would actually load. This is the same restriction that applies to tampering and it carries more weight here: editors remove their own temporary files as a routine part of committing a change, so a rule matching any file under the sensitive directory would report ordinary administration as policy deletion.

#### Scenario: Emptying a sudoers file fires

- **GIVEN** a `file_truncate` event for a path sudo will load
- **WHEN** the rule evaluates it
- **THEN** a finding is produced, reporting that the file was emptied

#### Scenario: Deleting a sudoers file fires

- **GIVEN** a `file_delete` event for a path sudo will load
- **WHEN** the rule evaluates it
- **THEN** a finding is produced, reporting that the file was deleted

#### Scenario: Destroying a file sudo ignores does not fire

- **GIVEN** a `file_delete` event for a name sudo skips, such as an editor's temporary file
- **WHEN** the rule evaluates it
- **THEN** no finding is produced, because no policy was destroyed

#### Scenario: Destruction and tampering carry different techniques

- **GIVEN** the rule covering destroyed sudo policy and the rule covering tampered sudo policy
- **WHEN** their ATT&CK mappings are read
- **THEN** they do not name the same technique, because one describes gaining elevated execution and the other describes removing access and evidence
