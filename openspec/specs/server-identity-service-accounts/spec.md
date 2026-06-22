# server-identity-service-accounts Specification

## Purpose

Defines API-only service accounts: non-human principals bound to a single seeded role that authenticate to the EDR API with short-lived, self-validating access tokens issued via client credentials, so automation and integrations call the API without a human session. Covers their lifecycle, credential handling, stateless token validation, revocation, and auditing.

## Requirements

### Requirement: A service account is a non-human principal bound to a single role

The system SHALL represent a service account as an identity of kind `api_token` with no associated human user, carrying a display name, an owning creator, exactly one bound seeded role, an expiry, and an enabled/revoked state. The expiry SHALL always be set, defaulted from the deployment-configured maximum credential lifetime and optionally shortened by the creator. The bound role MAY be any seeded role except `super_admin`, which the system MUST reject: a non-human credential carrying the unrestricted wildcard is never warranted. The `admin` role IS permitted at operator discretion, with the understanding that an admin-bound service account holds the console-management actions (`service_account.*`, `user.*`, `sso.manage`) and is therefore a full-control credential; operators SHOULD bind the least-privileged role that satisfies the automation. A verified service-account access token SHALL resolve to an actor carrying that bound role, evaluated by the same authorization chokepoint as a human operator.

#### Scenario: Service account binds to one role

- **GIVEN** an admin creates a service account bound to the `analyst` role
- **WHEN** that service account calls an API route
- **THEN** the request is authorized as an actor holding exactly the `analyst` role's actions
- **AND** no human user is associated with the call

#### Scenario: A service account cannot bind to super_admin

- **WHEN** an admin attempts to create a service account bound to `super_admin`
- **THEN** the system rejects the request without creating the service account

### Requirement: The client credential is hashed at rest and shown once

The system SHALL issue each service account a client credential consisting of a client id and a secret. The secret SHALL be returned in full exactly once, at creation or rotation, and MUST NOT be retrievable afterward. The system SHALL store only a one-way hash of the secret (SHA-256), never the plaintext, and MUST compare a presented secret against the stored hash in constant time. The credential carries a configurable maximum lifetime.

#### Scenario: Secret is returned once and never again

- **WHEN** an admin creates a service account
- **THEN** the response contains the full client secret exactly once
- **AND** a subsequent read of the service account returns metadata and whether a secret is set, but never the secret value

#### Scenario: Secret is stored hashed

- **GIVEN** a created service account
- **WHEN** its stored credential is inspected in the database
- **THEN** only a one-way hash of the secret is present, never the plaintext

### Requirement: The token endpoint issues short-lived self-validating access tokens

The system SHALL expose a token endpoint implementing the OAuth 2.1 client-credentials grant: a caller presents a valid, enabled, unexpired service-account credential and receives a short-lived signed access token, a `Bearer` token type, and an expiry. The access token SHALL be self-validating (signed under a key derived from the deployment root secret), carry the service-account subject, an audience bound to this deployment, the bound role/scope, an issued-at, an expiry of fifteen minutes, and a unique token id. The endpoint SHALL NOT issue a refresh token. A presented credential that is invalid, disabled, revoked, or expired SHALL be refused without issuing a token. Because it is an unauthenticated-by-session credential-exchange endpoint, it SHALL rate-limit requests per client id to bound brute-force and denial-of-service attempts, refusing requests that exceed the configured limit.

#### Scenario: Valid credential mints a short-lived token

- **GIVEN** an enabled, unexpired service-account credential
- **WHEN** the caller invokes the token endpoint with that credential
- **THEN** the response carries a signed `Bearer` access token expiring in fifteen minutes
- **AND** no refresh token is issued

#### Scenario: Revoked credential is refused

- **GIVEN** a service account that has been revoked
- **WHEN** the caller invokes the token endpoint with its credential
- **THEN** the endpoint refuses to issue a token

#### Scenario: The token endpoint rate-limits rapid requests

- **GIVEN** repeated token requests for one client id that exceed the configured rate limit
- **WHEN** the limit is exceeded
- **THEN** the endpoint refuses further requests for that client id until the window resets
- **AND** no access token is issued for the refused requests

### Requirement: Access tokens are validated statelessly on the API request path

The system SHALL authenticate an API request bearing a service-account access token by validating the token locally (signature, expiry, and audience) without a per-request database read, consistent with the stateless multi-replica topology. A token whose signature, expiry, or audience does not validate SHALL be rejected with `401 Unauthorized`. The audience binding MUST cause a token minted for one deployment to be rejected by another.

#### Scenario: Valid token authenticates without a database read

- **GIVEN** a valid, unexpired service-account access token
- **WHEN** it is presented as a bearer token on an API route
- **THEN** the request authenticates as the service-account principal
- **AND** validation does not require reading the service-account record per request

#### Scenario: Expired or wrong-audience token is rejected

- **WHEN** a request presents a service-account access token that is expired or carries an audience for a different deployment
- **THEN** the server returns `401 Unauthorized`

### Requirement: Revocation takes effect via short TTL and a per-replica epoch snapshot

The system SHALL make a service account revocable such that, after revocation or disabling, no new access token can be minted (the credential is refused) and any outstanding access token stops validating within a bounded refresh window. The system SHALL track a per-service-account epoch that is bumped on revoke/disable; each replica SHALL refresh a snapshot of these epochs from the durable store on a short interval and reject a presented token whose epoch is stale. The snapshot is a per-replica cache that is safe to lose and is rebuilt from the store.

#### Scenario: A revoked service account stops working within the refresh window

- **GIVEN** a service account with an outstanding, unexpired access token
- **WHEN** an admin revokes the service account
- **THEN** the credential can no longer mint new tokens immediately
- **AND** the outstanding token stops validating within the epoch-snapshot refresh window without requiring a server restart

### Requirement: Service-account lifecycle and token issuance are audited

The system SHALL emit an audit row for every service-account create, rotate, and revoke, and for every access-token issuance, recording the acting principal and the affected service account. No audit row MAY contain the client secret or the issued access token in any form.

#### Scenario: Creating a service account writes an audit row without the secret

- **WHEN** an admin creates a service account
- **THEN** an audit row records the acting user and the new service account
- **AND** the audit row contains no client secret

#### Scenario: Token issuance is audited

- **WHEN** a service account successfully obtains an access token
- **THEN** an audit row records the issuance for that service account
- **AND** the audit row contains no access-token value

### Requirement: Service accounts are managed from an admin surface behind the chokepoint

The system SHALL expose operator API endpoints to create, list, rotate, and revoke service accounts, each behind the operator-session middleware and the CSRF check for state-changing methods, funneling through the authorization chokepoint on the `service_account.*` actions. A caller lacking the required action SHALL receive `403 Forbidden` with the chokepoint reason. The system SHALL present a Service-accounts admin settings page, visible only to operators whose permission set includes the service-account management actions, that lists service accounts (name, role, created, last used, state), creates one (displaying the secret once), rotates a credential, and revokes a service account.

#### Scenario: Unauthorized caller cannot manage service accounts

- **GIVEN** an authenticated operator whose role does not grant the service-account management actions
- **WHEN** the operator requests a service-account management endpoint
- **THEN** the server returns `403 Forbidden` with the chokepoint reason

#### Scenario: Page is hidden without the grant

- **GIVEN** an authenticated operator whose permission set lacks the service-account management actions
- **WHEN** the operator opens the Admin settings area
- **THEN** the Service-accounts page is not offered
