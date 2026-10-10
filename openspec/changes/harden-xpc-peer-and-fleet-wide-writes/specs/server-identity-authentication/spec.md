## MODIFIED Requirements

### Requirement: Reauthentication is required for destructive actions

The system SHALL require a fresh authentication event within the configured reauth window (default 30 minutes for normal sessions; the same window applies to break-glass sessions) before authorizing a destructive action. The set of destructive actions in the current release MUST include host isolation, host process kill, host script run, host enrollment revocation, and dismissing an alert whose severity is `critical`. It MUST also include the deployment-wide writes that weaken every host at once: changing the addresses a contained host may still reach, changing rule content, and changing detection tuning (exclusions, per-rule mode and watched paths). A request whose session has not been re-authenticated within the window MUST be rejected with a typed error so the UI can prompt for re-authentication, and the rejection MUST be recorded in the audit log. A service-account token has no interactive session and is not subject to this gate; its role alone decides.

#### Scenario: Fresh session executes a destructive action

- **GIVEN** an authenticated session whose last fresh auth event is within the reauth window
- **WHEN** the operator invokes a destructive action that the policy would otherwise allow
- **THEN** the server proceeds with the action

#### Scenario: Stale session is challenged before destructive action

- **GIVEN** an authenticated session whose last fresh auth event is older than the reauth window
- **WHEN** the operator invokes a destructive action
- **THEN** the server returns a typed `reauth_required` error with the action and the reauth path
- **AND** an audit row is recorded with decision `deny` and reason `reauth_required`
- **AND** the action is not performed

#### Scenario: Fleet-wide change needs a fresh session

- **GIVEN** an admin session whose last fresh auth event is older than the reauth window
- **WHEN** the operator changes rule content, detection tuning or the reachable-address set, or revokes a host's enrollment
- **THEN** the server returns a typed `reauth_required` error and does not make the change
- **AND** the console prompts the operator to confirm their identity and then retries the change
