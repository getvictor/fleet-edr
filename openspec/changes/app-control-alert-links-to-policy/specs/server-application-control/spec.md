## MODIFIED Requirements

### Requirement: REST surface for policies, rules, groups, and assignments

The system SHALL expose the application control subsystem under `/api/v1/app-control/` with operator session authentication and CSRF protection on every state-changing call. The endpoints SHALL be:

- `GET /api/v1/app-control/policies` and `POST /api/v1/app-control/policies`
- `GET /api/v1/app-control/policies/{id}`, `PATCH /api/v1/app-control/policies/{id}`, `DELETE /api/v1/app-control/policies/{id}`
- `POST /api/v1/app-control/policies/{id}/rules` and `POST /api/v1/app-control/policies/{id}/rules:bulkUpsert`
- `GET /api/v1/app-control/rules/{id}`, `PATCH /api/v1/app-control/rules/{id}`, `DELETE /api/v1/app-control/rules/{id}`, `GET /api/v1/app-control/rules`
- `GET /api/v1/app-control/host-groups`, `POST /api/v1/app-control/host-groups`, `PATCH /api/v1/app-control/host-groups/{id}`, `DELETE /api/v1/app-control/host-groups/{id}`
- `POST /api/v1/app-control/policies/{id}/assignments`

A single rule SHALL be readable by its own id, returning the rule including the identifier of the policy that owns it. That ownership is not otherwise derivable by a client: an application-control alert records the rule it matched, not the policy, so without this read an operator holding an alert cannot reach the policy that blocked.

Successful responses SHALL be JSON. Errors SHALL follow the API capability's `ErrorResponse` shape. Each state-changing endpoint SHALL require a non-empty `actor` and `reason` field in the request body for audit.

#### Scenario: An unauthenticated request is rejected

- **GIVEN** a client without a valid session cookie
- **WHEN** the client calls any endpoint under `/api/v1/app-control/`
- **THEN** the server responds with HTTP 401 and the standard error shape

#### Scenario: A bulk upsert is idempotent on the unique key

- **GIVEN** a policy whose rules were created by a prior `bulkUpsert`
- **WHEN** the operator re-issues the identical `bulkUpsert` payload
- **THEN** the second run inserts zero new rules and updates the matching ones in place, because the `(rule_type, identifier)` unique key makes the upsert idempotent
- **AND** the policy ends with the same rule set

#### Scenario: A single rule is readable by its id

- **GIVEN** an operator with application-control read permission and a rule that exists
- **WHEN** the client calls `GET /api/v1/app-control/rules/{id}` for that rule
- **THEN** the response carries the rule, including the id of the policy that owns it
- **AND** a rule id that names no rule responds 404 with the standard error shape
- **AND** a caller without application-control read permission is refused, whatever the rule id
