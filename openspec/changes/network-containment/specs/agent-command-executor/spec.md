## ADDED Requirements

### Requirement: Set-network-containment command

The agent SHALL execute a `set_network_containment` command, whose payload carries `version`, `epoch` and `contained`, by sending the network extension a `network_containment.update` carrying those fields and, for a containment, the lifeline: the port of the endpoint the agent reaches the server through (the server, or the proxy for its URL), the addresses that endpoint resolves to, and its host name when it is not an IP literal. The agent SHALL resolve the lifeline by querying the configured resolvers directly, since the system resolver answers nothing on a contained host. The command SHALL complete only once the network extension reports that state applied, with a result naming the version, whether the host is contained, and the lifeline addresses. Commands SHALL run one at a time, so each confirmation is matched to the command that sent it. It SHALL fail, with the reason in its result, when the payload has no positive version or no `contained`, when the lifeline cannot be resolved (in which case nothing is sent), when the extension cannot be reached, when the extension reports the state not applied with an error or does not confirm within 15 seconds (a not-applied status with no error is pending, and the agent keeps waiting), when the extension reports the other `contained` value at the command's version, when the extension reports a newer state, and on a host without the network extension.

#### Scenario: The extension confirms the containment

- **GIVEN** an agent connected to the network extension
- **WHEN** it executes `set_network_containment` with `contained` true
- **THEN** it sends the extension the command's version and epoch with the resolved lifeline
- **AND** the command completes once the extension reports that version applied

#### Scenario: A containment whose lifeline cannot be resolved is not sent

- **GIVEN** an agent that cannot resolve the endpoint it reaches the server through
- **WHEN** it executes `set_network_containment` with `contained` true
- **THEN** it sends nothing to the extension and the command fails with the resolution error

#### Scenario: The extension does not apply the containment

- **GIVEN** an agent connected to the network extension
- **WHEN** the extension reports the command's state not applied with an error, the other `contained` value at the command's version, or a newer state, or reports nothing in time
- **THEN** the command fails with that reason

#### Scenario: A host without the network extension cannot contain

- **GIVEN** an agent with no network extension to contain with
- **WHEN** it executes `set_network_containment`
- **THEN** the command fails as not supported on the host

### Requirement: The server is reached through the lifeline

While the network extension reports the host contained, the agent SHALL connect to the endpoint it reaches the server through by the lifeline addresses it sent, trying each in turn with an equal share of the time left to connect, for its uploads and command polls, its token refresh and re-enrollment, and the control channel, because the system resolver answers nothing on a contained host. Connections to other destinations, and every connection while the host is not contained, SHALL be dialed as before. A control channel to a proxied server SHALL keep its own proxy dialing; it resolves the proxy with the system resolver, so while the host is contained that channel stays down and commands arrive by polling. Before its first connection to the server, the agent SHALL adopt the containment the network extension persisted, pinning its addresses, so an agent that must enroll on a contained host reaches the server; a state the extension reports SHALL replace it, and a persisted state that is not a containment, or names no usable address, SHALL leave the host uncontained.

#### Scenario: An agent starting on a contained host reaches the server

- **GIVEN** a contained host whose network extension persisted the containment and the lifeline addresses it holds
- **WHEN** the agent starts, before the extension has reported its status
- **THEN** its connections to the server go to those addresses, nothing is sent to the extension, and a persisted state that is not a containment leaves the host uncontained

#### Scenario: Contained dials use the lifeline

- **GIVEN** a contained host whose lifeline is two server addresses
- **WHEN** the agent connects to the server
- **THEN** it dials the first address, and the second when the first fails

#### Scenario: A released host dials the server by name

- **GIVEN** a host whose containment was released
- **WHEN** the agent connects to the server
- **THEN** it dials the server by name

### Requirement: The lifeline is kept current while contained

While the host is contained, the agent SHALL re-resolve its lifeline every five minutes and send the network extension an update at the current state's version and epoch when the addresses changed, and nothing when they did not. An update that could not be delivered SHALL be sent again at the next refresh or extension status, and SHALL NOT be dialed through until it is delivered. An agent that starts while the host is contained SHALL learn the containment from the extension's status and send the lifeline it resolves once. After its connection to the extension is re-established, the agent SHALL send the lifeline again on the next status, since a send over the dropped connection reports no delivery. Refreshes SHALL run one at a time. The extension's `ne_containment_status` control events SHALL be consumed by the agent and never uploaded as telemetry.

#### Scenario: A moved server address reaches the extension

- **GIVEN** a contained host
- **WHEN** the server's name resolves to different addresses at the next refresh
- **THEN** the agent sends the extension the new addresses at the same version and epoch

#### Scenario: An undelivered lifeline refresh is sent again

- **GIVEN** a contained host whose lifeline refresh could not be delivered to the network extension
- **WHEN** the extension next reports its status
- **THEN** the agent sends the lifeline again, and dials the server through those addresses only once it was delivered

#### Scenario: A reconnected extension is sent the lifeline again

- **GIVEN** a contained host whose agent sent the extension its lifeline
- **WHEN** the connection to the extension drops, is re-established, and the extension reports its status
- **THEN** the agent sends the lifeline again, and its dials stay pinned meanwhile

#### Scenario: A restarted agent refreshes the lifeline

- **GIVEN** an agent that starts on a host the network extension holds contained
- **WHEN** the extension reports that status
- **THEN** the agent sends the lifeline it resolves once, and not again for the same status

#### Scenario: Containment status is not uploaded

- **GIVEN** the network extension reports its containment status
- **WHEN** the agent receives it beside telemetry
- **THEN** the status is consumed and only the telemetry is queued for upload
