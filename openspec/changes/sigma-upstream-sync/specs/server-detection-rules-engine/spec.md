## ADDED Requirements

### Requirement: The vendored corpus is compared with upstream

The project SHALL be able to compare its vendored SigmaHQ macOS rules with one snapshot of upstream, across every upstream rule tree that has macOS rules, and report each rule upstream added, each it changed, each it moved to another category, and each vendored rule it no longer carries among its rules. A rule SHALL be matched by its rule id, not its path, so a moved rule is not read as one withdrawn and one added. A vendored rule that differs from upstream by any byte SHALL be reported as changed.

Bringing the corpus up to date SHALL copy new, changed and moved rules byte-for-byte, remove a moved rule's old copy, and regenerate the vendored manifest. It SHALL NOT delete a rule upstream withdrew, because upstream may have withdrawn it for a reason worth recording first. It SHALL NOT change the pinned import and refusal counts, so a new rule fails the corpus test until a person has read it. A downloaded file that does not match the snapshot SHALL leave the corpus unchanged.

#### Scenario: A corpus that matches upstream changes nothing

- **GIVEN** a vendored corpus identical to the upstream snapshot
- **WHEN** it is compared, and when it is brought up to date
- **THEN** no difference is reported and no file or manifest line changes

#### Scenario: New and changed upstream rules are copied verbatim

- **GIVEN** an upstream snapshot with a rule the corpus lacks, in a tree other than `rules/`, and a rule whose bytes differ from the vendored copy
- **WHEN** the corpus is compared
- **THEN** both are reported and nothing is written
- **AND** bringing it up to date writes both byte-for-byte under their log-source category and records them in the manifest

#### Scenario: A rule withdrawn upstream is reported and kept

- **GIVEN** a vendored rule upstream no longer carries among its rules, one of them moved to upstream's deprecated tree
- **WHEN** the corpus is brought up to date
- **THEN** each is reported as withdrawn, the moved one with where it went, and neither is deleted
