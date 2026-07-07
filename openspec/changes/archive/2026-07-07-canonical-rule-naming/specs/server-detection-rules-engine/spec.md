# Server Detection Rules Engine Specification (delta)

## ADDED Requirements

### Requirement: Canonical rule naming

The system SHALL give every detection rule one canonical human-readable name, distinct from its stable snake_case identifier, and reuse that one name across every operator-facing surface. The rule's documentation title (surfaced in `/api/rules` and `docs/detection-rules.md`) and the title of every alert the rule raises SHALL both be that canonical name, so an operator who triages an alert, reads the documentation, and writes an exclusion sees one name mapped to one rule. A rule that fires on more than one trigger arm SHALL still raise its findings under the single canonical name; the distinguishing arm detail belongs in the finding's description, not in a divergent title. The rule identifier SHALL remain unchanged by this requirement.

The application-control block rule is exempt from the alert-title half: its alerts carry a per-block computed title that names the blocked binary and a per-rule identifier (`app_control:<n>`) rather than the catalog rule's identifier, because those alerts name the admin rule and binary that were blocked rather than a catalog detection. Its documentation title SHALL still be the canonical name.

#### Scenario: A rule names itself the same way everywhere

- **GIVEN** any registered catalog rule other than the application-control block rule
- **WHEN** the rule's documentation title is read and the rule fires to raise an alert
- **THEN** the documentation title equals the rule's canonical name
- **AND** the alert's title equals that same canonical name
- **AND** the canonical name is a clean human-readable label carrying no parenthetical implementation detail

#### Scenario: A multi-arm rule raises one canonical title across arms

- **GIVEN** the `suspicious_exec` rule, which fires on either a temp-path exec arm or an outbound network-connection arm
- **WHEN** either arm fires
- **THEN** the alert title is the one canonical name "Suspicious exec chain"
- **AND** the finding description names which arm fired
