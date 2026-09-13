## MODIFIED Requirements

### Requirement: The agent distinguishes never-connected from connection-lost per extension

For each monitored extension the agent SHALL report reason `never_connected` while it has never established a session since the agent started, and reason `connection_lost` once it has established a session and then lost it while the agent continued running. When the receiver attributes a sustained connect failure to a staged upgrade (a previous version of the extension still registered until the Mac restarts), the agent SHALL instead report reason `reboot_required`, with a message saying a restart finishes the upgrade, until the next session is established. All three conditions SHALL carry status `unhealthy`.

#### Scenario: A fresh install with an unactivated extension reports never-connected

- **GIVEN** an agent that has started and never established the endpoint-security XPC session
- **WHEN** the registry is read
- **THEN** the `endpoint_security_extension` component reports status `unhealthy` with reason `never_connected`

#### Scenario: A dropped session reports connection-lost

- **GIVEN** an extension whose XPC session was established and then dropped while the agent kept running
- **WHEN** the registry is read
- **THEN** that component reports status `unhealthy` with reason `connection_lost`

#### Scenario: Upgrade awaiting restart says so

- **GIVEN** an agent whose network-extension receiver cannot connect because a previous version is waiting to be removed at the next restart
- **WHEN** the receiver emits its reboot-required signal
- **THEN** the `network_extension` component reports status `unhealthy` with reason `reboot_required` and a message saying to restart the Mac
- **AND** it reports its connected state again once a session is established

### Requirement: The agent maintains a per-component health registry

The agent SHALL maintain a health registry mapping each monitored component to a current condition carrying a status, a machine-readable reason, a human-readable message, and the timestamp the condition last changed. The registry SHALL be updated from the agent's existing per-service XPC connectivity state and its connect and disconnect transitions. The last-transition timestamp of a component SHALL advance only when that component's status or reason actually changes, so that the timestamp denotes the start of the current condition: a new reason at the same status, such as `never_connected` becoming `reboot_required`, is a new condition. A change to the status or reason SHALL be reported without waiting for the next periodic post.

#### Scenario: A connected extension is healthy

- **GIVEN** the endpoint-security extension XPC session is established
- **WHEN** the registry is read
- **THEN** the `endpoint_security_extension` component reports status `healthy` with reason `activated`

#### Scenario: The last-transition timestamp is stable across unchanged reads

- **GIVEN** a component whose status and reason have not changed since they were last set
- **WHEN** the registry is updated again with the same status and reason
- **THEN** the component's last-transition timestamp is unchanged
