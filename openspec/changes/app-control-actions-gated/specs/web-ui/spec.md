## ADDED Requirements

### Requirement: Application control rule controls follow their own permission

The application-control policy view SHALL hide a rule control from an operator whose permission set does not contain the action that control performs. Reading the page and changing a rule are separate permissions, so an operator who holds only the read action SHALL be offered no rule changes at all. Offering them is not a security hole, because the server refuses the call, but it costs the operator a dialog and an audit reason to be told what the page already knew.

Each control SHALL be gated on its own action rather than on a single writer permission. Promoting a rule to Protect, moving it back to Detect, editing it, and disabling or enabling it all change the rule through the same call, so one action gates them together; deleting a rule, adding one, and pasting many each have their own.

An operator offered no rule controls SHALL still see the rules. The view SHALL NOT present an actions column with nothing in it, and SHALL NOT instruct such an operator to use a control they cannot see.

Gating SHALL follow the permission set the server computed, and an absent permission set SHALL continue to render every control optimistically, because only the server can deny.

#### Scenario: A control is hidden without its own permission

- **GIVEN** an operator whose permission set contains the application-control read action but not the action a given rule control performs
- **WHEN** the operator opens a policy that holds a rule
- **THEN** that control is not rendered

#### Scenario: A control is shown with its own permission

- **GIVEN** an operator whose permission set contains the action a given rule control performs
- **WHEN** the operator opens a policy that holds a rule
- **THEN** that control is rendered

#### Scenario: A read-only operator still sees the rules

- **GIVEN** an operator whose permission set contains only the application-control read action
- **WHEN** the operator opens a policy
- **THEN** the rules and their details are shown
- **AND** no actions column is rendered
- **AND** an empty policy does not tell the operator to add the first rule
