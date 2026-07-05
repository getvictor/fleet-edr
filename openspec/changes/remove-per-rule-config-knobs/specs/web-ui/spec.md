# web-ui (delta: retire per-rule config knobs)

## MODIFIED Requirements

### Requirement: Per-rule documentation page

The UI SHALL provide a rule documentation page reachable by rule id from the coverage page and from the alert breadcrumb. The page MUST render the rule's title, summary, severity, ATT&CK technique mapping, event types, description, false-positive sources when present, and limitations when present. An unknown rule id MUST land on an empty state pointing back to the coverage page rather than producing a hard error.

#### Scenario: Rule detail renders documented fields

- **GIVEN** a registered rule with documentation
- **WHEN** the operator navigates to that rule's detail page
- **THEN** the UI renders the rule's title, summary, severity, ATT&CK techniques, event types, and description
- **AND** when the rule declares false positives or limitations, those sections render

#### Scenario: Unknown rule id renders a navigable empty state

- **GIVEN** a rule id that the server does not know about
- **WHEN** the operator navigates to that rule's detail page
- **THEN** the UI renders an empty state that links back to the ATT&CK coverage page
