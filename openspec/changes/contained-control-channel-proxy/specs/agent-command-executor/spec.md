## MODIFIED Requirements

### Requirement: The server is reached through the lifeline

While the network extension reports the host contained, the agent SHALL connect to the endpoint it reaches the server through by the lifeline addresses the extension reports its filter enforces, or by the addresses it sent where the extension does not report them, trying each in turn with an equal share of the time left to connect, for its uploads and command polls, its token refresh and re-enrollment, and the control channel, because the system resolver answers nothing on a contained host. Connections to other destinations, and every connection while the host is not contained, SHALL be dialed as before. A control channel to a proxied server SHALL reach the proxy by those same addresses and SHALL establish its own tunnel through it, naming the server inside the tunnel request rather than resolving it, so the channel reconnects while the host is contained; credentials carried by the proxy's own configured address SHALL be presented on that request, as they are for the agent's other traffic through the same proxy. A tunnel the proxy refuses SHALL fail the connection rather than yield one that carries nothing. Before its first connection to the server, the agent SHALL adopt the containment the network extension persisted, pinning its addresses, so an agent that must enroll on a contained host reaches the server; a state the extension reports SHALL replace it, and a persisted state that is not a containment, that the network extension would itself have refused, or that describes an endpoint other than the one the agent is configured for SHALL leave the host uncontained rather than be adopted in part.

#### Scenario: An agent starting on a contained host reaches the server

- **GIVEN** a contained host whose network extension persisted the containment and the lifeline addresses it holds
- **WHEN** the agent starts, before the extension has reported its status
- **THEN** its connections to the server go to those addresses, nothing is sent to the extension, and a persisted state that is not a containment, that names another endpoint, or that the extension would have refused leaves the host uncontained

#### Scenario: Contained dials use the lifeline

- **GIVEN** a contained host whose lifeline is two server addresses
- **WHEN** the agent connects to the server
- **THEN** it dials the first address, and the second when the first fails

#### Scenario: A released host dials the server by name

- **GIVEN** a host whose containment was released
- **WHEN** the agent connects to the server
- **THEN** it dials the server by name

#### Scenario: A proxied control channel tunnels through the proxy

- **GIVEN** a contained host whose agent reaches the server through a proxy named by host name
- **WHEN** the control channel connects
- **THEN** it dials the proxy's lifeline addresses, names the server only inside the tunnel request, and presents the credentials the proxy's configured address carries
- **AND** a tunnel the proxy refuses fails the connection rather than yielding one that carries nothing
