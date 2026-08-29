# Server detection rules engine: rule-file export delta

## ADDED Requirements

### Requirement: Detections are exportable as declarative rule files

The system SHALL render each registered detection as a declarative rule file carrying the rule's human-readable title, a stable identifier, its description, its severity, its MITRE ATT&CK technique identifiers, the platform and event category it applies to, its known false-positive sources, the event types it consumes, the exclusion dimensions it honours, and its known limitations.

The file SHALL name the evaluator that decides the rule. A rule whose logic is an implementation rather than a declarative expression is otherwise documented only by what it is for, never by what it does, and the evaluator name is what an operator cannot obtain without reading source.

The system SHALL NOT export a registered rule that is not a detection, for the reasons the catalog surface already omits them: a rule with no detection logic, no tuning surface, and no adversary claim has nothing to describe in a rule file.

The system SHALL state in each exported file why the rule will or will not run on another engine, so a reader of one file in isolation is not left to infer its portability.

Rendering SHALL fail rather than emit a partial file when a rule's metadata cannot produce a complete document. A rule file silently missing its severity or its event category reads as authoritative and is not.

#### Scenario: A detection exports as a rule file

- **GIVEN** a registered detection
- **WHEN** an operator requests its rule file
- **THEN** the file carries the rule's title, identifier, description, severity, techniques, event types, and limitations
- **AND** it names the evaluator that decides the rule

#### Scenario: A non-detection has no rule file

- **GIVEN** a registered rule that declares itself a projection or a health signal
- **WHEN** an operator requests its rule file
- **THEN** no rule file is produced for it

#### Scenario: Incomplete metadata is refused rather than half-rendered

- **GIVEN** a rule whose metadata omits the platform or the event types the file requires
- **WHEN** the system renders it
- **THEN** rendering fails and no partial file is produced

### Requirement: The exported rule pack matches the registered detections

The system SHALL keep the generated rule pack in agreement with the registered detections, covering exactly the detections that are registered and carrying their current content.

A pack that has drifted SHALL fail the build. A stale rule file is the more dangerous half of drift: a missing file is noticed the moment someone looks for it, whereas a file whose description or severity lags the rule reads as current and is wrong.

#### Scenario: A rule added without regenerating the pack fails the build

- **GIVEN** a detection registered with no corresponding file in the pack
- **WHEN** the pack is checked
- **THEN** the check fails and names the regeneration command

#### Scenario: A stale rule file fails the build

- **GIVEN** a rule file in the pack whose content no longer matches the registered rule
- **WHEN** the pack is checked
- **THEN** the check fails and identifies the stale file
