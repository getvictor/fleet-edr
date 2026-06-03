## ADDED Requirements

### Requirement: Navigation and action affordances are capability-gated

The UI SHALL hide navigation entries and action controls that the authenticated operator's effective
permission set - obtained from the session probe - does not authorize, so an operator is not shown
affordances they cannot use. A navigation entry SHALL be hidden when the permission set does not
contain the read action that gates its destination surface. An action control SHALL be hidden when the
permission set does not contain the action that the control performs. Gating SHALL be derived solely
from the server-provided permission set; the UI SHALL NOT contain its own mapping from role names to
permitted actions. Hiding an affordance is a usability measure only and SHALL NOT be relied upon as
access control; the server remains authoritative for every action.

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

### Requirement: Authorization denials degrade gracefully

The UI SHALL present an authorization denial as a clear, human-readable no-access state and SHALL NOT
surface a raw transport error such as `API error: 403`. When the server denies a request the UI
believed was permitted - for example because the operator's role changed after the session permission
set was fetched - the UI SHALL render the no-access state for that surface or action AND SHALL refresh
the permission set from the session endpoint so subsequent rendering reflects the operator's current
permissions. The refetch SHALL be deduplicated and throttled so that multiple gated components failing
at once, or repeated denials in quick succession, collapse to a single in-flight request rather than a
storm of session-endpoint calls. When the permission set is unavailable - for example an older server
that does not return one - the UI MAY render affordances optimistically but MUST still degrade any
resulting denial gracefully, so an absent permission set can never grant access; only the server can.

#### Scenario: Deep-link to a gated surface shows a no-access state

- **GIVEN** an operator whose permission set does not contain `application_control.read`
- **WHEN** the operator navigates directly to the Application control route
- **THEN** the UI shows a no-access message indicating the operator lacks access to that surface
- **AND** the UI does not display a raw `API error: 403`

#### Scenario: Mid-session revocation degrades and refetches

- **GIVEN** an operator who held an action and whose role binding was revoked after their session
  permission set was fetched
- **WHEN** the operator invokes the affected action and the server responds 403
- **THEN** the UI renders the no-access state for that action
- **AND** the UI refetches the session permission set so the corresponding affordance is hidden on
  subsequent renders

#### Scenario: Simultaneous denials collapse to one refetch

- **GIVEN** an operator whose role was revoked mid-session and a page that renders several gated
  affordances at once
- **WHEN** multiple of those affordances trigger an authorization denial in quick succession
- **THEN** the UI issues at most one in-flight refetch of the session permission set rather than one per
  denial
- **AND** subsequent renders reflect the refreshed permission set
