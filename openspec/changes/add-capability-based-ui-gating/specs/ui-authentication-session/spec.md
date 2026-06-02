## MODIFIED Requirements

### Requirement: Current-user lookup

The system SHALL expose a session-required GET that returns the currently authenticated operator's
identity AND the operator's effective permission set, so the UI can discover whether it is logged in,
which account is active, and which privileged actions the operator may perform, without re-prompting
for credentials and without a per-action round trip. The effective permission set SHALL be the
collection of action identifiers the operator is permitted under the active session's role bindings at
the deployment-wide scope, evaluated consistently with the authorization decision the server enforces.
A role that grants every action SHALL be expanded to the concrete action identifiers rather than
returning a wildcard token. The permission set SHALL be present for every authenticated session
regardless of whether it was established via SSO or via the break-glass surface. The permission set is
advisory to the UI for presentation only; no client SHALL treat it as authorization, and the server
SHALL continue to enforce every action at its authorization boundary independently of what the
permission set contained.

#### Scenario: Session probe while logged in

- **GIVEN** the client holds a valid session cookie for an operator bound to the `analyst` role
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the server returns 200 with the operator's identity, the session's CSRF token, and a
  permission set containing the analyst actions (for example `host.read`, `process.read`,
  `alert.read`, `alert.comment`)
- **AND** the permission set does not contain `host.kill_process` or `application_control.read`

#### Scenario: Higher-privilege role returns a superset

- **GIVEN** the client holds a valid session for an operator bound to `senior_analyst`
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the returned permission set additionally contains `host.kill_process`, `host.isolate`,
  `host.run_script`, and `application_control.read`

#### Scenario: All-actions role is expanded rather than wildcarded

- **GIVEN** the client holds a valid session for an operator whose role grants every action
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the returned permission set lists the concrete action identifiers from the action registry
- **AND** it does not contain a wildcard token such as `*`

#### Scenario: Session probe while logged out

- **GIVEN** the client has no session cookie or the cookie is invalid
- **WHEN** the client issues a GET to the session endpoint
- **THEN** the server returns 401 and no permission set is returned
