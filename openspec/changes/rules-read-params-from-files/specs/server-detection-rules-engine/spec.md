# Server detection rules engine: rules read their parameters from files delta

## ADDED Requirements

### Requirement: Detection parameters are read from the rule pack

The system SHALL read each detection's match values and decision thresholds from its rule file rather than from compiled-in constants, so that what a rule matches can be inspected and changed without reading or rebuilding source.

The system SHALL validate every parameter against a schema registered for the rule's evaluator rather than for the rule itself. Two rules sharing an evaluator therefore cannot disagree about which parameters it accepts, and one parameter name may mean different things under different evaluators without being reconciled.

The system SHALL refuse to start when a rule sets a parameter its evaluator never reads. A parameter nothing consults is worse than a missing one, because it invites an operator to believe they have tuned something.

The system SHALL refuse to start when a rule omits a parameter its evaluator reads, when a duration is unparseable or not positive, or when a match list is empty. Each refusal SHALL name the rule. Validation happens when the pack is loaded, so a bad value fails at start-up rather than at first fire, on one host, as a detection that silently did not happen.

The system SHALL NOT expose parameters that bound retrieval rather than the decision. Widening such a bound changes no finding and only widens a scan, while narrowing it causes silent false negatives, so no setting improves detection.

#### Scenario: A rule reads its match values from its file

- **GIVEN** a detection whose file declares its match values
- **WHEN** the engine loads the rule pack
- **THEN** the rule matches against the values in the file

#### Scenario: A parameter the evaluator never reads is refused

- **GIVEN** a rule file setting a parameter its evaluator does not read
- **WHEN** the pack is loaded
- **THEN** loading fails, naming the rule and the parameter

#### Scenario: A malformed parameter is refused at load

- **GIVEN** a rule file whose parameter is unparseable, not positive, or an empty match list
- **WHEN** the pack is loaded
- **THEN** loading fails, naming the rule

### Requirement: Values shared between rules are defined once

The system SHALL hold a match value used by more than one detection in a single shared definition rather than a copy in each rule's file.

Copying a shared value into every consumer's file leaves nothing keeping the copies equal, which is a weaker guarantee than the single definition it replaced. A value read by one rule belongs to that rule; a value read by code shared across rules belongs to the shared definitions.

The shared definitions are authored rather than generated, and the system SHALL preserve them when regenerating the pack.

#### Scenario: A shared value has one definition

- **GIVEN** a match value more than one detection uses
- **WHEN** an operator inspects the rule pack
- **THEN** the value is defined once and read by every consumer

#### Scenario: Regenerating the pack preserves the shared definitions

- **GIVEN** a rule pack containing authored shared definitions
- **WHEN** the pack is regenerated from the registered detections
- **THEN** the shared definitions are left intact
