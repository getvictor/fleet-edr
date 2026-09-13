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

#### Scenario: A rule moved upstream is moved, not kept twice

- **GIVEN** a vendored rule upstream now keeps in another category, or under a name differing only in case
- **WHEN** the corpus is brought up to date
- **THEN** the rule is written at its new path and its old copy is removed, so one rule id has one file

### Requirement: Upstream drift is checked weekly

A scheduled job SHALL compare the vendored corpus with upstream every week, and on demand, always from the main branch. When the corpus matches upstream it SHALL change nothing and close its open tracking issue, if there is one. When upstream differs, the job SHALL bring a copy of main up to date, regenerate the generated rule reference, run the catalog tests, and commit the result to a single review branch. It SHALL keep one open tracking issue carrying the comparison report, the test result, and a link to open a pull request from that branch. It SHALL NOT push to main, merge, or open the pull request itself. A failure to regenerate or to pass the tests SHALL be reported in the issue rather than stop the job, and a regeneration that fails SHALL leave the generated files as they were committed. The job SHALL NOT update a review branch that has an open pull request, nor one that changed after the job checked it, so a reviewer's commits are never overwritten. A difference that is only a withdrawn rule changes no file, so it SHALL be reported in the issue without a branch update.

#### Scenario: A matching corpus changes nothing and closes the report

- **GIVEN** a vendored corpus identical to upstream and an open tracking issue
- **WHEN** the weekly job runs
- **THEN** no branch is pushed and the tracking issue is closed

#### Scenario: Upstream changes reach a review branch and the report

- **GIVEN** an upstream rule that differs from its vendored copy, and no open pull request from the review branch
- **WHEN** the weekly job runs
- **THEN** the review branch carries the upstream bytes and the regenerated rule reference
- **AND** the tracking issue carries the report, the catalog test result, and a link that opens the pull request

#### Scenario: A withdrawal alone is reported without a branch change

- **GIVEN** a vendored rule upstream no longer carries, and no other difference
- **WHEN** the weekly job runs
- **THEN** the review branch is not updated and the tracking issue reports the withdrawn rule

#### Scenario: A pull request under review is left alone

- **GIVEN** an open pull request from the review branch
- **WHEN** the weekly job finds upstream changes
- **THEN** the review branch is not updated and the tracking issue links the open pull request
- **AND** the tracking issue still carries this run's test result

#### Scenario: A rule that breaks the corpus is still reported

- **GIVEN** an upstream change that makes the rule reference fail to regenerate or the catalog tests fail
- **WHEN** the weekly job runs
- **THEN** the review branch is still pushed, without a generated file the failure truncated, and the tracking issue carries the failing output
