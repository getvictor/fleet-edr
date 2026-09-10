# web-ui

## MODIFIED Requirements

### Requirement: ATT&CK coverage page

The UI SHALL provide a coverage page that renders the rule-to-technique mapping in the same shape the upstream MITRE ATT&CK Navigator uses, grouped by tactic. Each covered technique MUST link to its upstream MITRE reference, and the rule identifiers that cover a technique MUST link to that rule's documentation page. The page MUST also expose a control to download the underlying Navigator layer JSON.

Technique names and tactic assignments SHALL come from the published ATT&CK release the layer declares, not from a mapping maintained alongside the rules: a rule's tactic tags describe the rule rather than any one of its techniques, and a technique's tactics are a property of ATT&CK. A technique SHALL be rendered under every tactic ATT&CK assigns it, as the upstream matrix does, so a tactic covered only through a technique's secondary assignment is not shown as uncovered.

Where the page offers an action whose destination requires a permission the coverage page itself does not, it SHALL offer that action only to operators holding the destination's permission, so no operator is sent to a page they cannot open. The information beside such an action SHALL remain visible regardless.

#### Scenario: Coverage page renders technique groups

- **GIVEN** the server reports at least one covered technique
- **WHEN** the operator opens the coverage page
- **THEN** the UI renders technique rows grouped by ATT&CK tactic
- **AND** each technique id links to its upstream MITRE page
- **AND** each covering rule id links to that rule's documentation page

#### Scenario: A technique appears under every tactic it belongs to

- **GIVEN** a covered technique that ATT&CK assigns to more than one tactic
- **WHEN** the operator opens the coverage page
- **THEN** the technique is listed under each of those tactics
- **AND** its name is the one the published ATT&CK release gives it, not its bare identifier

#### Scenario: A tuning action is offered only where it can be followed

- **GIVEN** an operator without permission to read detection tuning
- **WHEN** the operator opens the coverage page
- **THEN** the count of techniques covered only by silent rules is still shown
- **AND** no link to the tuning page is offered

#### Scenario: Operator exports the Navigator layer

- **GIVEN** the coverage page is displayed
- **WHEN** the operator activates the export control
- **THEN** the browser downloads the Navigator layer JSON for the current coverage
