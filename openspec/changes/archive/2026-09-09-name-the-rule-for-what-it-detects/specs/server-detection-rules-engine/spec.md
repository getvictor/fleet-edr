# Server detection rules engine

## MODIFIED Requirements

### Requirement: Canonical rule naming

The system SHALL give every detection rule one canonical human-readable name, distinct from its stable snake_case identifier, and reuse that one name across every operator-facing surface. The rule's documentation title (surfaced in `/api/rules` and `docs/detection-rules.md`) and the title of every alert the rule raises SHALL both be that canonical name, so an operator who triages an alert, reads the documentation, and writes an exclusion sees one name mapped to one rule. A rule that fires on more than one trigger arm SHALL still raise its findings under the single canonical name; the distinguishing arm detail belongs in the finding's description, not in a divergent title. The rule identifier SHALL remain unchanged by this requirement.

The canonical name SHALL describe what the rule detects. A name that describes something else is a defect rather than a cosmetic matter: it tells an operator that a behaviour is covered when it is not, tells an analyst that something was observed when it was not, and it propagates, because documentation generated or written from a rule's name inherits the claim.

Correcting such a name SHALL NOT require changing the identifier, and the two are permitted to diverge. The identifier is a stable key that alerts, exclusions and per-rule settings are stored against, so changing it strands tuning and orphans alert history; the name is what operators read. Where they diverge, the rule SHALL record that the divergence is deliberate, so a later reader finds a decision rather than apparent drift.

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

#### Scenario: The canonical name may differ from the identifier

- **GIVEN** a rule whose identifier names a behaviour the rule does not detect
- **WHEN** its canonical name is corrected to describe what it detects
- **THEN** the identifier is unchanged, so stored exclusions, per-rule settings and historical alerts still resolve
- **AND** the rule records that the divergence between its name and its identifier is deliberate
