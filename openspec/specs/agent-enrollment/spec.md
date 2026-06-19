# Agent Enrollment Specification

## Purpose

Agent enrollment bootstraps a per-host identity that every subsequent agent-to-server interaction relies on. On first boot, the agent presents a deployment-wide shared secret along with the host's hardware UUID and receives back an opaque host token that scopes all of its later HTTP traffic. The token is then cached locally so day-two restarts do not re-spend the shared secret and do not generate spurious enrollment churn on the server.

The capability exists to draw a clean authentication boundary between "any process that knows the deployment secret" and "a specific enrolled host." Once a host is enrolled, the shared secret is no longer used for routine telemetry, command polling, or status updates; only the per-host token is. This lets operators rotate or revoke a single host without invalidating the rest of the fleet, and prevents a leaked agent token from being used to read any other host's data.

## Requirements

### Requirement: First-boot enrollment exchange

The system SHALL perform a one-time enrollment by POSTing the shared enroll secret and the host's hardware UUID to the server's enroll endpoint, and on success persist the returned host token before issuing any other authenticated request.

#### Scenario: Successful first enrollment

- **GIVEN** the agent has never enrolled and the deployment-wide enroll secret is configured
- **WHEN** the agent starts and contacts the server's enroll endpoint with the secret and the host's hardware UUID
- **THEN** the server responds 200 with a host identifier, an opaque host token, and an enrolled-at timestamp
- **AND** the agent persists the response to its on-disk token file before the call returns
- **AND** subsequent requests carry the host token in an Authorization Bearer header

#### Scenario: Hardware UUID is malformed

- **GIVEN** the agent's derived hardware UUID does not match the canonical hyphenated UUID form
- **WHEN** the agent posts to the enroll endpoint
- **THEN** the server returns 400 with an error code identifying the malformed identifier
- **AND** the agent does not persist any token file

#### Scenario: Enroll secret does not match

- **GIVEN** the agent presents a value other than the deployment's configured enroll secret
- **WHEN** the agent posts to the enroll endpoint
- **THEN** the server returns 401
- **AND** no enrollment row is created
- **AND** the failure is recorded in the server audit log

### Requirement: Token persistence is durable and private

The system MUST persist the host token at a configured path with file mode 0600 using a write-temp-then-rename sequence so a crash mid-write cannot leave a partial or readable token on disk.

#### Scenario: Atomic write on success

- **GIVEN** the agent has just received a host token from the server
- **WHEN** the agent persists the token file
- **THEN** the bytes are written to a sibling temporary file that is fsynced and then renamed over the final path
- **AND** the final file's permission bits are exactly 0600

#### Scenario: Token file is world-readable on load

- **GIVEN** a persisted token file exists with permissions broader than 0600
- **WHEN** the agent starts and attempts to load the file
- **THEN** the agent fails to start with an error identifying the insecure permissions
- **AND** the agent does not transmit the token to the server

#### Scenario: Token file is unreadable or malformed

- **GIVEN** a token file exists at the configured path but cannot be parsed as the expected schema
- **WHEN** the agent starts and attempts to load it
- **THEN** the agent fails to start with an error and does not silently fall back to a fresh enrollment

### Requirement: Restart reuses the persisted token

The system SHALL skip the enrollment exchange on subsequent startups whenever a valid token file is present at the configured path and the recorded server URL still matches the current configuration.

#### Scenario: Day-two restart with valid token

- **GIVEN** a token file exists with mode 0600 and the recorded server URL matches the current configuration
- **WHEN** the agent starts
- **THEN** the agent loads the token from disk and does not call the enroll endpoint
- **AND** the loaded host token is used for all authenticated requests

#### Scenario: Server URL has changed since enrollment

- **GIVEN** a token file exists but its recorded server URL differs from the current configuration
- **WHEN** the agent starts
- **THEN** the agent fails to start with an error instructing the operator to delete the file or reconfigure the URL
- **AND** the token is not transmitted to the new server

### Requirement: Re-enrollment on token revocation

The system SHALL re-enroll using the deployment secret when the server returns 401 for a previously valid host token, so that an operator-initiated revocation or a legitimate token rotation recovers without manual intervention.

#### Scenario: Server returns 401 mid-session

- **GIVEN** the agent is running with a persisted host token and the deployment secret is still configured
- **WHEN** any authenticated request returns 401 from the server
- **THEN** the agent attempts a fresh enrollment with the deployment secret
- **AND** on success it replaces the persisted token file atomically and resumes traffic

#### Scenario: Re-enroll attempts are throttled

- **GIVEN** the agent has just attempted a re-enrollment
- **WHEN** another 401 arrives within a short window after that attempt
- **THEN** the agent does not immediately retry
- **AND** the agent waits at least one minute between re-enroll attempts

#### Scenario: Re-enroll without the deployment secret

- **GIVEN** the agent was started with only a persisted token and no deployment secret in its environment
- **WHEN** the server returns 401
- **THEN** the agent logs an actionable error
- **AND** the agent does not loop on doomed re-enroll attempts

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

### Requirement: Enrollment is rate limited per source IP

The system SHALL rate limit enrollment attempts per source IP so that a misconfigured fleet behind a single egress address cannot exhaust the server, and so that brute-force attempts on the deployment secret remain expensive.

#### Scenario: Excess enroll attempts from one IP

- **GIVEN** an IP has exceeded the configured per-minute enroll attempt cap
- **WHEN** the IP issues another enroll attempt
- **THEN** the server returns 429 with a Retry-After header
- **AND** no enrollment row is created or modified

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

The server SHALL enforce revocation of self-validating tokens via a per-replica in-memory snapshot of hosts that are revoked or have had their token epoch bumped, loaded before the replica serves traffic and refreshed on a short interval. A token SHALL be rejected when its host is revoked or when the token's epoch is below the host's current epoch. Operator-driven credential cycling SHALL bump the host's token epoch (rather than minting and pushing a replacement token); the affected agent recovers by re-enrolling. A re-enrollment SHALL preserve the host's existing token epoch (never reset it) and mint the new token at that epoch, so an operator credential cycle is monotonic and is not undone by the agent's automatic re-enroll. The snapshot is a per-replica performance cache holding no state a peer replica needs. The replica SHALL fail closed on the initial load: if the snapshot cannot be loaded before serving, the replica SHALL refuse to start rather than serve with an empty (allow-all) snapshot. On a later runtime refresh failure the previous snapshot SHALL be retained rather than dropped to empty. On a successful (re-)enrollment the replica SHALL record the host's post-enrollment state (not revoked, at the preserved epoch) in its local snapshot so the newly issued token is accepted immediately on that replica while any token below that epoch stays rejected; other replicas converge within their refresh interval.

#### Scenario: Operator rotate invalidates after the snapshot refreshes

- **GIVEN** an enrolled host with a valid token
- **WHEN** an operator cycles the host's credentials (bumping its token epoch) and the snapshot refreshes
- **THEN** the host's pre-rotate token is rejected with 401
- **AND** a re-enrollment by that host mints a fresh token that verifies

#### Scenario: Re-enrollment preserves the token epoch

- **GIVEN** a host whose credentials an operator has cycled (token epoch bumped) and whose pre-rotate token is rejected
- **WHEN** the host re-enrolls
- **THEN** the freshly minted token verifies
- **AND** the pre-rotate token remains rejected, because the bumped epoch is preserved across the re-enrollment rather than reset

#### Scenario: Snapshot refresh failure retains the previous view

- **GIVEN** a populated revocation snapshot on a replica
- **WHEN** a subsequent refresh from the database fails
- **THEN** the replica continues enforcing the previously loaded revocation state
- **AND** does not fail open by dropping to an empty snapshot
