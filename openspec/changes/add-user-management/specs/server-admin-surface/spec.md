## MODIFIED Requirements

### Requirement: Authenticated admin boundary

The server MUST gate every endpoint defined by this capability behind both the
operator-session middleware AND the authorization chokepoint defined by the
server-identity-authorization capability, so a caller that is not authenticated as an
operator SHALL receive `401 Unauthorized` and a caller whose role does not grant the
endpoint's required action SHALL receive `403 Forbidden`. The endpoints in this
capability — `/api/enrollments`, `/api/enrollments/{host_id}/revoke`, `/api/policy`,
`/api/attack-coverage`, `/api/rules`, `/api/users`, `/api/users/{id}`,
`/api/users/{id}/role-bindings`, `/api/roles` — each MUST declare the action the
chokepoint will be asked to authorize (for example, `host.read` for the enrollments
listing, `host.revoke_enrollment` for revoke, `policy.read` for policy GET,
`policy.write` for policy PUT, `user.read` for user listing, `user.invite` for user
creation, `role.bind` for role bindings). The implicit "any authenticated operator is
admin" model is no longer in effect; the chokepoint is the source of truth.

#### Scenario: Unauthenticated request is rejected

- **GIVEN** a client that has not authenticated
- **WHEN** the client requests any endpoint defined by this capability
- **THEN** the server returns `401 Unauthorized`
- **AND** the response body uses the standard error shape `{"error": "..."}`

#### Scenario: Authenticated operator without permission is rejected

- **GIVEN** a client holding a valid session whose role does not grant the action
  required by the endpoint
- **WHEN** the client requests that endpoint
- **THEN** the server returns `403 Forbidden`
- **AND** an audit row is recorded with decision `deny` and the chokepoint's reason
- **AND** the response body uses the standard error shape `{"error": "..."}`

#### Scenario: Authorized operator request proceeds

- **GIVEN** a client holding a valid session whose role grants the action required by
  the endpoint at the requested resource's scope
- **WHEN** the client requests the endpoint and satisfies any required CSRF check for
  the HTTP method
- **THEN** the request is dispatched to the corresponding admin handler
- **AND** an audit row is recorded with decision `allow` (subject to read-sampling
  rules for read endpoints)

## ADDED Requirements

### Requirement: List users

The system SHALL expose `GET /api/users` returning the set of users known to the
deployment. Each entry MUST identify the user (id, email, display name, status), the
authentication methods they have bound (one or more identity rows summarized as a list
of `{kind, provider}` pairs), the role bindings they hold (one or more role names with
their scope), and the timestamp of their last successful authentication. The endpoint
MUST require the `user.read` action.

#### Scenario: Operator with `user.read` lists users

- **GIVEN** at least one user exists and the caller's role grants `user.read`
- **WHEN** the operator requests `GET /api/users`
- **THEN** the server returns `200 OK` with a JSON array of user rows
- **AND** every row identifies the user, their identity bindings, and their role bindings

#### Scenario: Caller without `user.read` is forbidden

- **GIVEN** a session whose role does not grant `user.read`
- **WHEN** the operator requests `GET /api/users`
- **THEN** the server returns `403 Forbidden`

### Requirement: Disable a user

The system SHALL expose `POST /api/users/{id}/disable` that flips a user's `status`
column to `disabled` and revokes every active session bound to that user. The endpoint
MUST require the `user.disable` action and MUST refuse to disable a user whose
`is_breakglass=1` flag is set. A successful disable MUST emit an audit row with action
`user.disabled` and the actor user id.

#### Scenario: Disable a regular user

- **GIVEN** an SSO-provisioned user with `is_breakglass=0` and an active session
- **WHEN** an operator with `user.disable` POSTs to `/api/users/{id}/disable`
- **THEN** the server returns `204 No Content`
- **AND** the user's `status` is `disabled`
- **AND** any active sessions bound to that user are removed
- **AND** an audit row is recorded with action `user.disabled`

#### Scenario: Disabling a break-glass account is refused

- **GIVEN** the break-glass user with `is_breakglass=1`
- **WHEN** an operator POSTs to `/api/users/{id}/disable` for that user
- **THEN** the server returns a typed error (HTTP 4xx) and does not modify the user
- **AND** the audit log records the rejection

### Requirement: Bind and unbind a role

The system SHALL expose `POST /api/users/{id}/role-bindings` to bind a role to a user
and `DELETE /api/users/{id}/role-bindings/{binding_id}` to remove a binding. Both
endpoints MUST require the `role.bind` action. The bind endpoint's request body MUST
identify the role and MAY identify a `scope_type` and `scope_id`; in wave 1 the only
honored `scope_type` is `tenant`, and a request specifying a non-tenant scope MUST be
persisted (per the authorization spec) but MUST emit a warning in the response payload
so the operator knows the binding will not yet take effect. Both bind and unbind MUST
emit an audit row.

#### Scenario: Operator binds an analyst role at tenant scope

- **GIVEN** an operator with `role.bind`
- **WHEN** the operator POSTs `/api/users/{id}/role-bindings` with `role='analyst'`
  and `scope_type='tenant'`
- **THEN** the server returns `201 Created` with the new binding's id
- **AND** an audit row is recorded with action `role.bound`

#### Scenario: Operator unbinds a role

- **GIVEN** an existing role binding for a user
- **WHEN** an operator with `role.bind` DELETEs
  `/api/users/{id}/role-bindings/{binding_id}`
- **THEN** the server returns `204 No Content`
- **AND** an audit row is recorded with action `role.unbound`

#### Scenario: Caller without `role.bind` is forbidden

- **GIVEN** a session whose role does not grant `role.bind`
- **WHEN** the operator attempts to bind or unbind a role
- **THEN** the server returns `403 Forbidden`

### Requirement: Read the role catalog

The system SHALL expose `GET /api/roles` returning the role catalog. Each entry MUST
include the role name, its description, the `is_builtin` flag, and the list of
permissions it grants. The endpoint MUST require the `role.read` action and SHALL be
available to roles that include role-binding work in their scope (`super_admin`,
`admin`).

#### Scenario: Admin reads the role catalog

- **GIVEN** an operator with `role.read`
- **WHEN** the operator requests `GET /api/roles`
- **THEN** the server returns `200 OK` with the five seeded roles
- **AND** each role entry carries its name, description, `is_builtin=true`, and
  permission list
