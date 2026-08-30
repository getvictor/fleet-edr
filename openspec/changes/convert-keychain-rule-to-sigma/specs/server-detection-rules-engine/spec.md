# Server detection rules engine: a converted rule carries its logic in its file delta

## ADDED Requirements

### Requirement: A converted rule carries its logic in its file

The system SHALL evaluate a detection whose logic is a Sigma `detection:` block in its rule file, rather than a function in the engine.

The system SHALL compile every such block, and check every field it reads against the taxonomy for its logsource category, when the rule catalog is built. A block that does not compile, names a field the event type does not supply, or declares a category for which no fields are supplied SHALL prevent start-up. Deferring any of these to evaluation would produce a rule that loads cleanly and then never matches, which cannot be told apart from the behaviour never occurring.

A rule SHALL declare what decides it in exactly one way: a detection block, or the name of an engine evaluator. Carrying both would point a reader at code that no longer decides anything, and carrying neither leaves a rule file that cannot say what the rule does.

The system SHALL treat a rule's detection block as authored rather than generated, and regeneration SHALL re-emit it unchanged, comments included.

#### Scenario: A detection block is compiled and checked when the pack loads

- **GIVEN** a rule file carrying a detection block that reads a field its event type does not supply
- **WHEN** the rule catalog is built
- **THEN** it fails, naming the field

#### Scenario: A converted rule detects what it detected before

- **GIVEN** a detection converted from an engine implementation
- **WHEN** the events that exercised the original are replayed
- **THEN** it produces the same findings

### Requirement: Portability is derived from the rule rather than declared

The system SHALL derive a rule's kind and portability from the rule itself: whether it carries a detection block, and whether the fields that block reads come from Sigma's own taxonomy or are computed by this engine.

The system SHALL report a rule reading only taxonomy fields as portable to any Sigma-compatible engine, one reading a computed field as valid Sigma that needs fields only this engine supplies, and one with no detection block as not portable at all. Each rule file SHALL state the reason, so a reader of one file in isolation learns why it will or will not run elsewhere.

Portability is a promise made to whoever reads the file about whether they can run the rule, so it is derived rather than asserted by hand.

#### Scenario: Portability is derived from the rule rather than declared

- **GIVEN** a rule whose detection block reads a field this engine computes
- **WHEN** its file is generated
- **THEN** the file reports it as valid Sigma requiring fields only this engine supplies, and explains why
