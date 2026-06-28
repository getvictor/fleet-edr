## MODIFIED Requirements

### Requirement: Authentication outcomes write an audit row

The system SHALL record an audit row for every authentication outcome, success or failure, regardless of authentication method. Action names MUST follow the pattern `auth.<flow>.<outcome>` where `<flow>` is one of `oidc` or `breakglass` (named after the _flow_ that produced the outcome, not the credential type: the break-glass flow combines a local password and a WebAuthn assertion under a single `breakglass` flow so dashboards stay cohesive). The action name MUST be one of `auth.oidc.success`, `auth.oidc.failure`, `auth.oidc.callback.error`, `auth.breakglass.success`, or `auth.breakglass.failure`. The row MUST include the request timestamp, the source IP, the user agent, the request id, the action name, the decision (`allow`, `deny`, or `error`), the reason, and the acting principal (its type, its principal id, and a snapshot display label). The principal id MAY be null ONLY for a pre-authentication failure where no principal was resolved; such a row MUST still record the attempted identifier in the label so a brute force across identifiers is visible. Audit row writes MUST NOT block on the user response: a write failure SHALL be logged at ERROR and counted as a metric but the user request continues.

#### Scenario: Successful SSO login is audited with the user principal

- **GIVEN** a successful Okta OIDC callback that mints a session
- **WHEN** the response is sent
- **THEN** an audit row exists with `action='auth.oidc.success'`, `decision='allow'`, the actor principal of type `user` with its principal id and snapshot label, and the request id

#### Scenario: Failed break-glass login records the attempted identifier without a principal id

- **GIVEN** a break-glass login attempt with a wrong password
- **WHEN** the server validates the submission
- **THEN** the client receives a generic invalid-credentials response
- **AND** the audit row records `action='auth.breakglass.failure'`, a null principal id, the attempted identifier in the label, and the precise failure reason in the row's `reason` field (e.g. `password_mismatch`, `webauthn_assertion_invalid`)

### Requirement: Authorization decisions on state-changing actions write an audit row

The system SHALL record an audit row for every authorization decision on a state-changing action, including allow, deny, and error outcomes. Every such row MUST name the acting principal by its type, principal id, and snapshot display label, and MUST NOT collapse the actor to an empty or zero value regardless of whether the actor is a human user or a service account. Read-only actions SHALL be sampled at a configurable fraction (`audit.read_sampling`, default `0.0` in the current release). When the actor is a break-glass account, the read-sampling fraction MUST be treated as `1.0` regardless of configuration so every break-glass action is auditable end-to-end.

#### Scenario: State-changing allow names the acting principal

- **GIVEN** an authorization decision of `allow` on a state-changing action (for example, host isolate)
- **WHEN** the chokepoint records the decision
- **THEN** an audit row exists with `decision='allow'`, the action name, the resource type and id, and the acting principal's type, id, and snapshot label

#### Scenario: A service-account action is attributed to the service account, not to nobody

- **GIVEN** a service-account actor performing a state-changing action
- **WHEN** the chokepoint records the decision
- **THEN** the audit row names a principal of type `service_account` with the service account's principal id and label, never an empty or zero actor

#### Scenario: A deleted user's history resolves its snapshot label without a join

- **GIVEN** an audit row written for a user who is later deleted
- **WHEN** the audit log is read back
- **THEN** the row still shows the actor's principal id and the label captured at action time, with no join to a mutable user row
