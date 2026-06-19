# agent-enrollment (delta: self-validating signed host tokens)

## MODIFIED Requirements

### Requirement: Per-host token scoping

The system MUST issue tokens that are scoped to a single host so that one host's token cannot read or write data that belongs to any other host. Revocation of a host's token is enforced by the per-replica revocation snapshot and therefore takes effect within the snapshot refresh interval (a bounded eventual consistency across replicas), rather than instantaneously on every replica.

#### Scenario: Token cannot read another host's commands

- **GIVEN** host A and host B both hold valid host tokens
- **WHEN** host A polls the command endpoint with its own token but a query identifying host B
- **THEN** the server does not return host B's commands
- **AND** the server treats the request as scoped to host A regardless of any host identifier in the query

#### Scenario: Revoking a host invalidates its token

- **GIVEN** an operator revokes a specific host's enrollment
- **WHEN** the revocation has propagated to a replica's revocation snapshot (within the refresh interval) and that host presents its previously valid token
- **THEN** the server returns 401
- **AND** the agent's re-enroll path engages on the next request

## REMOVED Requirements

### Requirement: Host tokens are stored and verified with a fast keyed hash

**Reason**: Superseded by self-validating signed tokens. Verification no longer fetches an enrollment row or recomputes a stored keyed hash; the token authenticates itself by signature, removing the per-request database lookup from the authenticated hot path. The keyed-hash columns remain in the schema but are no longer consulted for verification (their removal is a fast-follow).

**Migration**: Hard cutover. Tokens issued under the keyed-hash model fail signature verification and the affected hosts recover through the existing re-enrollment-on-revocation path.

## ADDED Requirements

### Requirement: Host tokens are self-validating signed tokens

The server SHALL issue each host token as a self-validating signed token that carries the host identity, a revocation epoch, an issued-at time, and an absolute expiry, signed with a server-held HMAC-SHA256 key. The server SHALL verify a presented token by recomputing the HMAC under that key, comparing with a constant-time check, and validating the expiry, WITHOUT any database access on the authenticated hot path. The signing key SHALL be derived from the required server root secret (`EDR_SECRET_KEY`, with the `*_FILE` fallback) via HKDF-SHA256 under a fixed versioned domain-separation label distinct from the storage pepper. Every verification failure (bad signature, wrong key id, malformed, expired) SHALL surface to the agent as an indistinguishable 401 so the wire is not an oracle. The enroll response SHALL carry the token's absolute expiry.

#### Scenario: Issued token verifies without a database lookup

- **GIVEN** a host completes enrollment and receives a signed token plus its expiry
- **WHEN** the host presents that token on an authenticated request
- **THEN** the server accepts it by verifying the signature and expiry locally, with no enrollment-row read
- **AND** the request is scoped to the host_id carried in the token's claims

#### Scenario: A tampered or expired token is rejected

- **GIVEN** a token whose signature does not verify under the server key, or whose expiry is in the past
- **WHEN** the host presents that token
- **THEN** the server rejects the request with 401
- **AND** the rejection does not distinguish tampering from expiry from an unknown host

### Requirement: Agent refreshes its token before expiry

The agent SHALL proactively refresh its host token before the token's expiry by calling a dedicated refresh endpoint that is gated by the same host-token authentication as other agent routes, so a continuously running host never lets its token lapse. The refresh endpoint SHALL re-verify the presented token and mint a fresh token for the host at the host's current revocation epoch, rejecting the request (401) when the token's epoch is below the host's current epoch. This closes the revocation-snapshot staleness window: a stale-epoch token that the eventually-consistent snapshot still accepts at the middleware MUST NOT be refreshed into a current-epoch token. The agent SHALL also check refresh-eligibility immediately on startup, not only on its periodic timer, so a token already near expiry after a restart or resume is refreshed promptly. A refresh that is rejected with 401 (the host has been revoked or its epoch bumped) SHALL cause the agent to fall back to the re-enrollment path.

#### Scenario: Refresh issues a fresh token

- **GIVEN** an enrolled host with a valid, unexpired token
- **WHEN** the agent calls the refresh endpoint with that token
- **THEN** the server returns a fresh signed token and its new expiry
- **AND** the new token verifies on subsequent requests

#### Scenario: Refresh after revocation re-enrolls

- **GIVEN** a host whose enrollment has been revoked and the revocation is visible in the snapshot
- **WHEN** the agent calls the refresh endpoint with its current token
- **THEN** the server returns 401
- **AND** the agent engages its re-enrollment path

### Requirement: Revocation is enforced by a per-replica snapshot

The server SHALL enforce revocation of self-validating tokens via a per-replica in-memory snapshot of hosts that are revoked or have had their token epoch bumped, loaded before the replica serves traffic and refreshed on a short interval. A token SHALL be rejected when its host is revoked or when the token's epoch is below the host's current epoch. Operator-driven credential cycling SHALL bump the host's token epoch (rather than minting and pushing a replacement token); the affected agent recovers by re-enrolling. The snapshot is a per-replica performance cache holding no state a peer replica needs. The replica SHALL fail closed on the initial load: if the snapshot cannot be loaded before serving, the replica SHALL refuse to start rather than serve with an empty (allow-all) snapshot. On a later runtime refresh failure the previous snapshot SHALL be retained rather than dropped to empty.

#### Scenario: Operator rotate invalidates after the snapshot refreshes

- **GIVEN** an enrolled host with a valid token
- **WHEN** an operator cycles the host's credentials (bumping its token epoch) and the snapshot refreshes
- **THEN** the host's pre-rotate token is rejected with 401
- **AND** a re-enrollment by that host mints a fresh token that verifies

#### Scenario: Snapshot refresh failure retains the previous view

- **GIVEN** a populated revocation snapshot on a replica
- **WHEN** a subsequent refresh from the database fails
- **THEN** the replica continues enforcing the previously loaded revocation state
- **AND** does not fail open by dropping to an empty snapshot
