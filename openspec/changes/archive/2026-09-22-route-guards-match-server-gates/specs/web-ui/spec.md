## MODIFIED Requirements

### Requirement: Navigation and action affordances are capability-gated

The UI SHALL hide navigation entries and action controls that the authenticated operator's effective permission set (obtained from the session probe) does not authorize, so an operator is not shown affordances they cannot use. A navigation entry SHALL be hidden when the permission set does not contain the read action that gates its destination surface. An action control SHALL be hidden when the permission set does not contain the action that the control performs. Gating SHALL be derived solely from the server-provided permission set; the UI SHALL NOT contain its own mapping from role names to permitted actions. Hiding an affordance is a usability measure only and SHALL NOT be relied upon as access control; the server remains authoritative for every action.

The action a surface is gated on SHALL be the action the server gates that surface's own data on. A surface gated on more than the server asks refuses an operator the server would have answered, which is a page withheld from someone entitled to it rather than a safety margin. A surface gated on less is reached and then fails, which is how a raw transport error arrives at an operator who should have been told they lack access. Neither direction is safe by default, so neither is the one to guess.

A surface SHALL NOT be left ungated in order to give the landing redirect something to resolve to. An operator holding no actions has no surface to land on, and saying so is the honest answer; sending them to whichever surface happens to be ungated answers with that surface's own failure instead.

Where one page reads a surface the operator may not hold, that part of the page SHALL be gated on its own action rather than the page's. A page admitted on one action does not thereby admit every call it makes.

#### Scenario: Application control entry hidden without read access

- **GIVEN** an operator whose permission set does not contain `application_control.read`
- **WHEN** the authenticated application renders its navigation
- **THEN** the Application control navigation entry is not shown
- **AND** navigating directly to the Application control route does not present the surface

#### Scenario: Application control entry shown with read access

- **GIVEN** an operator whose permission set contains `application_control.read`
- **WHEN** the navigation renders
- **THEN** the Application control navigation entry is shown

#### Scenario: Kill process control hidden without the action

- **GIVEN** an operator whose permission set does not contain `host.kill_process`
- **WHEN** the operator opens a process's detail
- **THEN** the Kill process control is not rendered

#### Scenario: Kill process control shown with the action

- **GIVEN** an operator whose permission set contains `host.kill_process`
- **WHEN** the operator opens a process's detail
- **THEN** the Kill process control is rendered and can be invoked

#### Scenario: The rule catalogue is reached on the action its data needs

- **GIVEN** an operator whose permission set contains `alert.read` and not `rule_content.read`
- **WHEN** the operator opens the rule catalogue
- **THEN** the catalogue is presented
- **AND** the rules it lists are shown

#### Scenario: A rule's detail and its monitor records follow the catalogue

- **GIVEN** the same operator
- **WHEN** they open a rule's detail, and that rule's monitor records
- **THEN** both are presented

#### Scenario: The built-in rules panel is gated on its own action

- **GIVEN** an operator holding `alert.read` and not `rule_content.read`
- **WHEN** they open the rule catalogue
- **THEN** the panel reporting which built-in rules the deployment runs is not rendered
- **AND** no failed read of it is shown in its place

#### Scenario: Coverage is gated rather than relied on as a landing

- **GIVEN** an operator whose permission set contains no actions
- **WHEN** they sign in and are redirected to a landing surface
- **THEN** they are shown the no-access state
- **AND** they are not shown a raw transport error
