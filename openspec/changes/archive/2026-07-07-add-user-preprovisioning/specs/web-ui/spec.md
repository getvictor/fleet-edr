## ADDED Requirements

### Requirement: The users page pre-provisions a new user and distinguishes the pending state

The web UI SHALL provide an "Add user" control on the user-management page that opens a form taking an email and a bindable role and submits it to the pre-provisioning API, then refreshes the list. The control SHALL be gated on the operator's `user.invite` permission via the `useCan()` seam: an operator lacking the grant SHALL NOT be shown the control. A pre-provisioned account (status `provisioned`) SHALL be rendered with a distinct pending indicator so it is visually distinguishable from active and disabled users immediately after creation.

#### Scenario: An admin pre-provisions a user from the users page

- **GIVEN** an admin viewing the user-management page who holds `user.invite`
- **WHEN** they open the add-user form, enter an email and select a role, and submit
- **THEN** the email and role are sent to the pre-provisioning API
- **AND** the refreshed list shows the new user with a pending indicator

#### Scenario: The add-user control is hidden without the invite grant

- **GIVEN** an operator viewing the user-management page who does not hold `user.invite`
- **WHEN** the page renders
- **THEN** the add-user control is not shown
