## MODIFIED Requirements

### Requirement: Peer code-signing validation

The extensions SHALL reject any inbound XPC connection whose peer does not satisfy a code-signing requirement chained to the Apple anchor, the Fleet Device Management team identifier, and the agent's code-signing identifier `fleet-edr-agent`. All three MUST hold together: a binary signed with the team identifier but any other code-signing identifier SHALL be rejected. The validation MUST run before any event is delivered to the peer and before any inbound message from the peer is processed.

Implementations MUST use `xpc_connection_set_peer_code_signing_requirement` (macOS 13+) as the sole peer-validation gate. Implementations MUST NOT additionally call `SecCodeCheckValidity`, `SecCodeCopyGuestWithAttributes`, or any other user-side variant of the same check against the same requirement string. The rationale and threat model are documented in [ADR-0007](../../../docs/adr/0007-xpc-peer-validation-libxpc-only.md).

A debug-configured extension MAY additionally accept the locally-built ad-hoc agent by its fixed code-signing identifier alone so dev iteration works on a SIP-disabled developer VM (a `go build` ad-hoc signature carries no team ID and would otherwise fail the production requirement). The debug path SHALL pin a stable identifier rather than a content-derived code-directory hash, so it does not go stale on every agent rebuild. This debug acceptance SHALL be excluded from release builds, so production peer validation always requires the anchor, the team identifier and the agent identifier together.

#### Scenario: A peer with the wrong team ID is rejected

- **GIVEN** an extension's XPC service is listening
- **WHEN** a process signed with a team ID other than `FDG8Q7N4CC` attempts to connect
- **THEN** the extension cancels the connection
- **AND** the rejected peer never receives any events
- **AND** any inbound message from that peer is discarded

#### Scenario: A team-signed peer with another identifier is rejected

- **GIVEN** a release-configured extension's XPC service is listening
- **WHEN** a process signed with team ID `FDG8Q7N4CC` but a code-signing identifier other than `fleet-edr-agent` attempts to connect
- **THEN** the extension cancels the connection
- **AND** the peer can neither receive events nor deliver containment, application-control or watched-path documents

#### Scenario: An ad-hoc-signed peer is rejected in production builds

- **GIVEN** a release-configured extension's XPC service is listening
- **WHEN** a process without a chain to the Apple anchor attempts to connect
- **THEN** the extension cancels the connection

#### Scenario: An ad-hoc-signed peer is accepted in debug builds by its signing identifier

- **GIVEN** a debug-configured extension's XPC service is listening, built to accept the dev agent by its fixed code-signing identifier for local-iteration use on a SIP-disabled developer VM
- **WHEN** a process ad-hoc-signed with the dev agent's code-signing identifier attempts to connect
- **THEN** the connection is accepted
- **AND** the peer is added to the broadcast set
- **AND** the identifier is stable across agent rebuilds, so no re-pinning of the extension is required when the agent is rebuilt
- **AND** this code path is excluded from release builds, so it cannot weaken production peer validation

#### Scenario: A correctly-signed agent is accepted

- **GIVEN** an extension's XPC service is listening
- **WHEN** a process signed with the hardened runtime, team ID `FDG8Q7N4CC` and the code-signing identifier `fleet-edr-agent` connects
- **THEN** the connection is accepted
- **AND** the peer is added to the broadcast set
