## ADDED Requirements

### Requirement: A file rule is imported when hosts watch its paths

An imported Sigma rule in a file category (`file_event`, `file_rename`, `file_delete`) SHALL be imported only when every search in its detection constrains `TargetFilename`, and each condition in it that pins a directory (equality, `startswith` or `contains`) can be met by a path every host watches: the extension's built-in paths and the server's default watched paths, compared through `/private`. A rule the check cannot prove, including one with a search that does not constrain `TargetFilename`, a regular expression, or only `endswith`, SHALL be refused with a reason naming the paths every host watches, since the agent emits file events only for watched paths and such a rule could never fire.

#### Scenario: A file rule inside the watched set is imported

- **GIVEN** a file rule whose every search pins `TargetFilename` inside a path every host watches
- **WHEN** the corpus loads
- **THEN** the rule is imported

#### Scenario: A file rule it cannot prove is refused

- **GIVEN** a file rule with a search outside every watched path, with no `TargetFilename`, with a regular expression, or with only `endswith`
- **WHEN** the corpus loads
- **THEN** the rule is refused, and the reason names the paths every host watches
