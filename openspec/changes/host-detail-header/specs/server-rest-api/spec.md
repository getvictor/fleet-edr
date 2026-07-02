## ADDED Requirements

### Requirement: Host detail endpoint

The system SHALL expose `GET /api/hosts/{host_id}` returning one host's identity and liveness: the host identifier, the enrollment hostname, the OS product name, OS version, and OS build, the agent version, the source IP recorded at enrollment, the enrollment time, the timestamp of the inventory report that last refreshed identity, the most recent time any event from the host was observed, the count of events seen, and the server-computed agent-health rollup. The endpoint SHALL be authorized by the same host-read action as the host list. An unknown host identifier MUST return 404; a host that has sent events but has no enrollment record MUST still return, with empty identity fields, matching the list endpoint's posture.

#### Scenario: Operator fetches host detail

- **GIVEN** an enrolled host that has sent events and posted an inventory check-in
- **WHEN** the client calls `GET /api/hosts/{host_id}`
- **THEN** the response carries the hostname, OS name/version/build, agent version, source IP, enrolled-at, last-seen, event count, and health rollup for that host

#### Scenario: Unknown host id returns 404

- **GIVEN** a host identifier no host row matches
- **WHEN** the client calls `GET /api/hosts/{host_id}`
- **THEN** the response status is 404

#### Scenario: Never-enrolled host returns empty identity

- **GIVEN** a host that has sent events but has no enrollment record
- **WHEN** the client calls `GET /api/hosts/{host_id}`
- **THEN** the response returns with empty identity fields rather than 404
