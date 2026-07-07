## ADDED Requirements

### Requirement: The agent maintains a per-component health registry

The agent SHALL maintain a health registry mapping each monitored component to a current condition carrying a status, a machine-readable reason, a human-readable message, and the timestamp the condition last changed. The registry SHALL be updated from the agent's existing per-service XPC connectivity state and its connect and disconnect transitions. The last-transition timestamp of a component SHALL advance only when that component's status actually changes, so that the timestamp denotes the start of the current condition.

#### Scenario: A connected extension is healthy

- **GIVEN** the endpoint-security extension XPC session is established
- **WHEN** the registry is read
- **THEN** the `endpoint_security_extension` component reports status `healthy` with reason `activated`

#### Scenario: The last-transition timestamp is stable across unchanged reads

- **GIVEN** a component whose status has not changed since it was last set
- **WHEN** the registry is updated again with the same status
- **THEN** the component's last-transition timestamp is unchanged

### Requirement: The agent distinguishes never-connected from connection-lost per extension

For each monitored extension the agent SHALL report reason `never_connected` while it has never established a session since the agent started, and reason `connection_lost` once it has established a session and then lost it while the agent continued running. Both conditions SHALL carry status `unhealthy`.

#### Scenario: A fresh install with an unactivated extension reports never-connected

- **GIVEN** an agent that has started and never established the endpoint-security XPC session
- **WHEN** the registry is read
- **THEN** the `endpoint_security_extension` component reports status `unhealthy` with reason `never_connected`

#### Scenario: A dropped session reports connection-lost

- **GIVEN** an extension whose XPC session was established and then dropped while the agent kept running
- **WHEN** the registry is read
- **THEN** that component reports status `unhealthy` with reason `connection_lost`

### Requirement: The agent posts an idempotent status snapshot

The agent SHALL post its current health as a complete snapshot to the host check-in endpoint, authenticated with its host token, carrying the agent version and the full list of component conditions on every post. The snapshot SHALL be idempotent: re-posting the same state SHALL leave the server's view unchanged, and each post SHALL fully replace the prior snapshot for that host rather than appending to a log.

#### Scenario: A post carries the full component list

- **GIVEN** a registry holding the endpoint-security and network-extension components
- **WHEN** the agent posts a status snapshot
- **THEN** the request carries the agent version and both components with their status, reason, message, and last-transition timestamp

#### Scenario: Re-posting an unchanged snapshot is a no-op for the server view

- **GIVEN** a snapshot the agent has already posted successfully
- **WHEN** the agent posts the identical snapshot again
- **THEN** the server's stored health for that host is unchanged

### Requirement: The agent reports on startup, on transition, and periodically

The agent SHALL post a status snapshot shortly after startup, again whenever a component's status changes, and on a periodic floor while running. Transition-triggered posts SHALL be debounced so a burst of connect retries collapses into a single post.

#### Scenario: A startup post makes a dead sensor visible immediately

- **GIVEN** an agent starting with an extension that never connects
- **WHEN** the agent has started
- **THEN** it posts a snapshot showing that extension `unhealthy` without waiting for the periodic floor

#### Scenario: A status change triggers a post

- **GIVEN** a running agent that has already posted a snapshot
- **WHEN** an extension transitions from connected to lost
- **THEN** the agent posts an updated snapshot reflecting the transition

#### Scenario: A burst of retries collapses into one post

- **GIVEN** an extension failing to connect and retrying rapidly with no change in resulting status
- **WHEN** several retries occur within the debounce window
- **THEN** the agent posts at most one snapshot for that burst
