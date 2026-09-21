## ADDED Requirements

### Requirement: Rules can be written in the console

An operator with `rule_content.write` SHALL be able to create a rule, edit and delete a rule the deployment wrote, and roll back the shipped rules, without leaving the web UI. An operator without `rule_content.write` SHALL NOT be offered any of these. A rule the server reports as shipped SHALL NOT be opened for editing, however its editor is reached, since shipped rules are tuned rather than rewritten.

Before a rule is saved, the UI SHALL show whether its document is valid, as answered by the server's dry run, and SHALL present a refusal as the rule's problem in the loader's own words. The dry run judges the document alone, so the UI SHALL NOT claim a passing check means the deployment will load the rule: a conflict with the deployment's other rules is decided on save, and a refusal then SHALL also be shown in the loader's words. Saving SHALL require a passing check of the content being saved, so an edit made after a check SHALL require a new check before it can be saved, a check that answers after such an edit SHALL NOT count, and a save refused because the rules changed meanwhile SHALL require a new check too.

Every change SHALL require a reason, recorded with the change. A newly created rule SHALL be marked, at the point of creation, as raising no alert until it is promoted, with the way to promote it. Because the server applies stored rules only when it next reloads them, the UI SHALL say so after a change, and the page a create opens SHALL wait for the new rule to be loaded rather than report it as unknown.

The UI SHALL report whether the deployment runs the shipped rules the running build carries, and which rules differ when it does not. A rollback SHALL name any shipped rule it did not restore.

#### Scenario: An operator creates a rule with a reason

- **GIVEN** an operator with `rule_content.write` on the new rule page
- **WHEN** they enter an identifier and a document that passes the check, save it, and give a reason
- **THEN** the document is stored under that identifier with that reason, and the rule's page opens

#### Scenario: A new rule's page waits for the server to load it

- **GIVEN** an operator who has just created a rule the server has not yet reloaded
- **WHEN** the rule's page opens
- **THEN** it says it is waiting for the server to load the rule, and shows the rule once the server serves it
- **AND** it calls the rule unknown only after a reload should have happened

#### Scenario: An invalid rule is explained before anything is written

- **GIVEN** a document the loader refuses
- **WHEN** the operator checks it
- **THEN** the loader's reason is shown as the rule's problem
- **AND** the document cannot be saved

#### Scenario: A shipped rule is not opened for editing

- **GIVEN** an operator with `rule_content.write`
- **WHEN** they open the editor of a rule the server reports as shipped, for example by typing its address
- **THEN** the editor does not load the rule's document and says the rule is tuned in Detection tuning instead

#### Scenario: A new rule says it will not alert until promoted

- **GIVEN** an operator creating a rule
- **WHEN** the new rule page renders
- **THEN** it says the rule runs in monitor mode until promoted, and links to where rules are promoted

#### Scenario: An operator deletes a rule with a reason

- **GIVEN** an operator with `rule_content.write` on the page of a rule the deployment wrote
- **WHEN** they delete it and give a reason
- **THEN** the document is deleted with that reason
- **AND** a shipped rule's page offers no edit or delete, and neither does any page for an operator without `rule_content.write`

#### Scenario: An operator rolls back the shipped rules with a reason

- **GIVEN** an operator with `rule_content.write` and a previous set of shipped rules to return to
- **WHEN** they roll back and give a reason
- **THEN** the previous set is restored with that reason, and any shipped rule not restored is named
