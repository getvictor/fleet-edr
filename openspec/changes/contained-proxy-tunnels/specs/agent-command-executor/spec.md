## MODIFIED Requirements

### Requirement: The server is reached through the lifeline

While the network extension reports the host contained, the agent SHALL connect to the endpoint it reaches the server through by the lifeline addresses the extension reports its filter enforces, or by the addresses it sent where the extension does not report them, trying each in turn with an equal share of the time left to connect, for its uploads and command polls, its token refresh and re-enrollment, and the control channel, because the system resolver answers nothing on a contained host. Connections to other destinations, and every connection while the host is not contained, SHALL be dialed as before. A control channel to a proxied server SHALL reach the proxy at the same address the lifeline pins for it and SHALL establish its own tunnel through it, naming the server inside the tunnel request rather than resolving it, so the channel reconnects while the host is contained. The agent SHALL take the dial over only for a proxy whose protocol it speaks, and SHALL leave any other proxy dialed as before, because a proxy sent a request it cannot parse would be worse off than one that is merely unreachable while contained: the request carries the credentials the operator configured on it. The protocols the agent speaks SHALL be HTTP and HTTPS proxies, tunnelled with CONNECT, and SOCKS5 proxies, tunnelled with their own handshake. A SOCKS5 proxy SHALL be given the server as a NAME to resolve rather than an address, because a contained host cannot resolve it. An HTTPS proxy SHALL be spoken to over TLS before any bytes are written to it, so the credentials on the tunnel request do not cross the path in the clear, and that TLS SHALL use the configuration the agent applies to its own traffic through the same proxy, differing only in the name verified, which SHALL be the proxy's; a stricter configuration would fail only the control channel while the agent's uploads and polls kept working, which presents as the fault this requirement exists to remove. Credentials carried by that address SHALL be presented on the tunnel request, as they are for the agent's other traffic through the same proxy. A tunnel the proxy refuses SHALL fail the connection rather than yield one that carries nothing. A tunnel whose caller has given up SHALL fail promptly rather than wait out the network: a proxy that accepts a connection and then says nothing would otherwise hold a dial nobody is waiting for until the socket itself failed. The deadline that bounds establishing the tunnel SHALL NOT remain on the connection afterwards, because the stream that runs over it is long-lived and would be torn down when that deadline passed. Before its first connection to the server, the agent SHALL adopt the containment the network extension persisted, pinning its addresses, so an agent that must enroll on a contained host reaches the server; a state the extension reports SHALL replace it, and a persisted state that is not a containment, that the network extension would itself have refused, or that describes an endpoint other than the one the agent is configured for SHALL leave the host uncontained rather than be adopted in part.

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
- **AND** a proxy whose protocol the agent does not speak is dialed as it was before, rather than being sent a request it cannot parse along with its credentials
- **AND** a tunnel the proxy refuses fails the connection rather than yielding one that carries nothing
- **AND** a tunnel whose caller has given up fails promptly rather than waiting out a proxy that has gone silent
- **AND** no deadline from establishing the tunnel remains on the connection the stream then runs over

#### Scenario: A SOCKS5 proxy is spoken to in its own protocol

- **GIVEN** a contained host whose agent reaches the server through a SOCKS5 proxy named by host name
- **WHEN** the control channel connects
- **THEN** it reaches the proxy at the pinned address, completes a SOCKS5 handshake rather than sending a CONNECT, and hands the proxy the server as a name to resolve
- **AND** the credentials the proxy's configured address carries are offered in that handshake

#### Scenario: An HTTPS proxy is reached over TLS first

- **GIVEN** a contained host whose agent reaches the server through an HTTPS proxy
- **WHEN** the control channel connects
- **THEN** the first bytes it writes open a TLS handshake, not a tunnel request that would carry the operator's credentials in the clear
- **AND** the proxy's certificate is verified against the proxy's own name under the configuration the agent applies to its other traffic through that proxy
- **AND** a certificate that configuration rejects fails the connection with a message naming the proxy
