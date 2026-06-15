# Server identity authentication: root-secret-derived signing keys delta

## ADDED Requirements

### Requirement: Pre-auth cookie signing keys derive from the deployment root secret

The server SHALL sign its pre-authentication cookies (the OIDC state cookie carrying state + nonce + PKCE verifier, and the break-glass WebAuthn challenge-state cookie) with an HMAC key derived from the deployment root secret (`EDR_SECRET_KEY`) via HKDF-SHA256 under a fixed versioned domain-separation label, rather than from a dedicated signing-key environment variable. The root secret SHALL be required on every boot, with the standard `*_FILE` fallback, and the server SHALL refuse to boot when it is absent or shorter than 32 bytes. The server SHALL NOT read a separate `EDR_SESSION_SIGNING_KEY`.

Because the signing key is derived deterministically from the root, every replica that shares the root secret derives the same signing key, so a state or challenge cookie minted on one replica verifies on another. Rotating the root secret changes the derived signing key, which invalidates every active session and every in-flight OIDC sign-in and break-glass ceremony; operators re-authenticate. The same root secret also seeds the host-token HMAC pepper (see the agent-enrollment delta), so a deployment provisions one secret rather than one per purpose.

#### Scenario: Server requires the root secret at boot

- **GIVEN** a server configuration with no `EDR_SECRET_KEY` (and no `EDR_SECRET_KEY_FILE`)
- **WHEN** the server loads its configuration
- **THEN** boot fails with an error naming `EDR_SECRET_KEY`
- **AND** a value shorter than 32 bytes fails boot with a length error

#### Scenario: OIDC state cookie is signed with the derived key

- **GIVEN** a server booted with a valid `EDR_SECRET_KEY` and OIDC enabled
- **WHEN** the login handler mints the OIDC state cookie and the callback later verifies it
- **THEN** the cookie is signed and verified with the key derived from the root secret under the session-signing label
- **AND** no separate `EDR_SESSION_SIGNING_KEY` is consulted

#### Scenario: Replicas sharing the root secret verify each other's pre-auth cookies

- **GIVEN** two server replicas configured with the same `EDR_SECRET_KEY`
- **WHEN** one replica mints an OIDC state cookie and the matching callback is served by the other replica
- **THEN** the second replica derives the same signing key and verifies the cookie successfully
