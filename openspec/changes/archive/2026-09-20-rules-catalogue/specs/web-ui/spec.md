## ADDED Requirements

### Requirement: The rule catalogue is browsable

The web UI SHALL offer a catalogue of every rule the deployment runs, reachable from the top navigation for an operator with `rule_content.read`. An operator cannot judge or change what a deployment detects without first being able to see it, and a rule page reachable only by deep link from an alert does not let them.

Each catalogue entry SHALL show the rule's name, identifier, severity, and the mode it runs in, and SHALL say whether that mode was set by an operator. Each entry SHALL say whether the rule shipped with the product or was written on this deployment, and a shipped rule SHALL credit its author where the server reports one. That distinction SHALL come from the provenance the server reports, not from a document's path.

A rule's page SHALL show the rule document it is loaded from, as written, to an operator with `rule_content.read`. A rule built into the server is not loaded from a stored rule document, and its page SHALL say so. An operator without `rule_content.read` SHALL NOT be offered the document.

#### Scenario: An operator browses the rules the deployment runs

- **GIVEN** an operator with `rule_content.read`
- **WHEN** they open the rule catalogue from the top navigation
- **THEN** every rule the deployment runs is listed with its name, identifier, severity, and mode in force, each linking to its rule page
- **AND** a mode an operator set is marked as set

#### Scenario: The catalogue distinguishes shipped rules from the deployment's own

- **GIVEN** a deployment running shipped rules and rules written on it
- **WHEN** the catalogue renders
- **THEN** each rule is marked as shipped or as the deployment's own, with a shipped rule's author credited
- **AND** the operator can narrow the list to either

#### Scenario: An operator reads a rule as written

- **GIVEN** an operator with `rule_content.read` on the page of a rule loaded from a rule document
- **WHEN** the page renders
- **THEN** it shows that document verbatim with its path
- **AND** a built-in rule's page says it has no stored document, and an operator without `rule_content.read` is offered none
