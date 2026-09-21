# extension-network-response Specification

## Purpose

Defines the network extension's DNS-forwarding resilience: a health watchdog that monitors upstream-forwarding health and recovers from sustained failure without operator intervention. When no enforcement policy is active it fails open (resolution returns to the system resolver, availability preserved) and periodically attempts to restore proxying; when a policy is active it never bypasses in a way that would let a blocked domain resolve.

## Requirements

### Requirement: DNS proxy forwards away from another provider's tunnel

An enabled DNS proxy becomes the sole resolver for every flow it claims, so its own upstream forward MUST NOT be routed back into a resolver that is waiting on that forward. When another network extension owns the system default route, forwarding that extension's own resolver query over the default route sends it into that extension's tunnel; it cannot answer until the forward completes, and the forward cannot complete until it answers, so all host name resolution stops.

The system SHALL determine whether a claimed flow originated from another network-extension provider, identified by that process holding the network-extension entitlement rather than by a list of known vendors, and SHALL route that flow's upstream forward so that it cannot leave over a tunnel interface. The system's own provider is exempt: it holds the same entitlement, and the operating system already keeps the system's own outbound connections out of the proxy chain, so no dependency cycle exists.

For every other claimed flow, the system SHALL pin the upstream forward to the interface the client bound its flow to, when the flow reports one, so a forward cannot be silently re-routed onto a path the client did not choose. A flow that is not bound to an interface SHALL keep default routing. A tunnel-avoiding forward SHALL NOT be pinned to the flow's bound interface, because that interface may itself be the tunnel being avoided.

The system MUST NOT decline a DNS flow in order to keep out of another resolver's path. Declining does not return the flow to the operating system: a declined flow is not resolved by any other path, so declining costs the host its name resolution entirely rather than failing open. Forward outcomes for tunnel-avoiding flows SHALL NOT contribute to the forwarding-health accounting that triggers a bypass, because those forwards are denied the tunnel by design and would otherwise drive the system toward a bypass on a host whose only route is a tunnel.

Routing a provider's forwards away from tunnels SHALL be observable once per provider rather than once per flow, so a provider that resolves continuously cannot flood the log.

#### Scenario: A forward for another network extension provider avoids tunnel interfaces

- **GIVEN** DNS proxying is enabled and another network extension that is itself a resolver is running
- **WHEN** a DNS flow whose source process holds the network-extension entitlement is claimed
- **THEN** the system forwards the query without using any tunnel interface
- **AND** the flow is still claimed, so `dns_query` telemetry is emitted for it

#### Scenario: An ordinary flow honours the interface the client bound

- **GIVEN** DNS proxying is enabled and a claimed flow reports that it is bound to a specific interface
- **WHEN** the system forwards the query upstream
- **THEN** the forward leaves on the interface the flow was bound to rather than following the system default route

#### Scenario: The system's own provider takes ordinary routing

- **GIVEN** DNS proxying is enabled
- **WHEN** a DNS flow attributed to the system's own network extension is claimed
- **THEN** the system routes its forward as an ordinary flow, because the operating system already excludes the system's own outbound connections from the proxy chain

#### Scenario: Tunnel-avoiding forwards do not drive the health watchdog

- **GIVEN** DNS proxying is enabled and forwards for another provider's flows are failing because the only available route is a tunnel
- **WHEN** the forwarding-health accounting is updated
- **THEN** those outcomes are excluded, so they cannot trigger a bypass

#### Scenario: A provider routed away from tunnels is reported once

- **GIVEN** DNS proxying is enabled and another network-extension provider is resolving continuously
- **WHEN** many of its DNS flows are forwarded away from tunnel interfaces
- **THEN** the system reports that provider once rather than once per flow

### Requirement: DNS proxy reports forwarding degradation without leaving the DNS path

An enabled DNS proxy is the configured resolver for every flow it claims, and declining a flow terminates that flow rather than returning it to the operating system. The system therefore MUST NOT decline a DNS flow as a recovery action, and MUST NOT treat declining as a way to fail open. A claimed flow stays claimed.

When an upstream forward fails or reaches its deadline, the system SHALL attempt the query against another resolver from the system DNS configuration before giving up, but ONLY when the resolver the client addressed is itself part of that configuration. When the client addressed a resolver that is not in the system configuration, the system MUST NOT substitute a different one, because a substituted resolver can legitimately answer differently and would answer a question the client did not ask. An answer obtained from a substitute resolver SHALL be returned to the client as though it came from the resolver the client originally addressed.

Each forward attempt SHALL be bounded by a deadline, and the total time a client can be made to wait across all attempts SHALL be bounded. When no attempt can answer, the system SHALL release the flow so the client fails promptly rather than being pinned.

The system SHALL account upstream-forwarding outcomes over a recent window and SHALL report a sustained failure rate as degraded, and a return to working as recovered, reporting each change once rather than per forward. That report is observational: it MUST NOT change whether flows are claimed.

#### Scenario: Sustained forwarding failure is reported as degraded

- **GIVEN** DNS proxying is enabled
- **WHEN** upstream forwards fail continuously past the health threshold
- **THEN** the system reports forwarding as degraded, once rather than per forward
- **AND** the system continues to claim DNS flows

#### Scenario: A query to a system resolver is retried against another system resolver

- **GIVEN** DNS proxying is enabled and the system DNS configuration lists more than one resolver
- **WHEN** a forward to one of those resolvers fails or reaches its deadline
- **THEN** the system attempts the query against a different resolver from the system configuration
- **AND** an answer from that resolver is returned to the client as though it came from the resolver it originally addressed

#### Scenario: A query to a client chosen resolver is not retried elsewhere

- **GIVEN** DNS proxying is enabled and a client addresses a resolver that is not in the system DNS configuration
- **WHEN** the forward to that resolver fails or reaches its deadline
- **THEN** the system does not substitute a different resolver

#### Scenario: Forwarding recovery is reported

- **GIVEN** forwarding has been reported as degraded
- **WHEN** upstream forwards start succeeding again
- **THEN** the system reports forwarding as recovered, once rather than per forward

### Requirement: Containment is enforced by the operating system

The network extension SHALL enforce host network containment as content-filter settings whose default action drops every flow the lifeline does not allow, so the operating system enforces it without consulting the provider: new and established connections to other destinations are cut, and containment stays in force while the provider is stopped or restarting. A contained host SHALL keep a lifeline of TCP to each EDR server address it was given on the server port, DHCP between the client and server ports (UDP 68 to 67, and UDP 546 to 547 for DHCPv6), and outbound DNS (TCP and UDP 53) to the host's configured resolvers, at most eight of them, and to no other address, allowing none when no resolver is known; loopback is not filtered. The extension SHALL re-read the configured resolvers while a host is contained and apply the settings again when they change, including a list read after a starting filter chose its settings. Which names a contained host may resolve is the DNS proxy's restriction, below, and is not in force when that provider is not running. A host that is not contained SHALL have the filter's telemetry settings, which hand every flow to the provider, except that a release SHALL keep TCP to the released containment's EDR server endpoint, and to the endpoint a lifeline refresh last replaced since the content filter started, allowed by rule until the content filter next starts. The lifeline rules decide the connections the agent opens while the host is contained, so the provider never sees them, and the operating system cuts such a connection once it is handed to a provider that never saw it, together with the release command's outcome on its way to the server. The kept server flows record no `network_connect` events.

#### Scenario: A contained host keeps only the lifeline

- **GIVEN** a containment naming an EDR server address and port
- **WHEN** the extension builds the filter rules for it
- **THEN** the rules allow TCP to that address on that port, DHCP from the client port to the server port, and DNS, and nothing else

#### Scenario: Contained DNS reaches only the configured resolvers

- **GIVEN** a contained host whose configured resolvers are known
- **WHEN** the extension builds the filter rules for it
- **THEN** the rules allow DNS to each of those resolvers and to no other address, and a host with no known resolver is allowed no DNS

#### Scenario: Resolvers that move under a contained host apply

- **GIVEN** a contained host whose filter settings name the resolvers known when they were applied
- **WHEN** the host's configured resolvers change, including a list first read after the filter chose its settings
- **THEN** the extension applies settings naming the new resolvers, and a list that did not change asks for no apply

#### Scenario: Releasing a host restores the telemetry settings

- **GIVEN** a host that is not contained
- **WHEN** the extension builds the filter rules for it
- **THEN** there are no lifeline rules, and the filter uses its telemetry settings

#### Scenario: A release keeps the server flows allowed

- **GIVEN** a contained host whose agent opened connections to the EDR server while contained
- **WHEN** the containment is released
- **THEN** TCP to the containment's server addresses and port, and to the endpoint its last lifeline refresh replaced, stays allowed by rule, and every other flow is handed to the provider
- **AND** a later release keeps those rules, a starting content filter does not apply them, and a release after the start keeps none from before it

### Requirement: A contained host resolves only the EDR server's name

While the host is contained, the network extension's DNS proxy SHALL forward a DNS query only when it is a single-question query for one of the lifeline's names, compared case-insensitively and without a trailing dot label by label, and SHALL forward it rebuilt from its ID, opcode, recursion-desired flag and question, with every other flag clear, so nothing a process appends after the question leaves the host; the query's ID and destination remain the process's choice. The one exception is the UDP payload size, which the rebuilt query SHALL carry in an OPT record of the proxy's own making, and only when what followed the client's question was a lone minimal OPT record: a root name, type OPT, a size, no extended response code, no EDNS version but 0, no flag set including DNSSEC-OK, no option data, and nothing after it. Anything else, including a record that is not an OPT and a byte too many, SHALL leave the query rebuilt with no record at all, which is what every such query got before this. The size the rebuilt record carries SHALL be the one the client offered, clamped to between 512 and 1232: an offer above that is lowered, because a larger answer risks fragmentation, and an offer below it is raised, because 512 is both what a responder treats any smaller offer as and what a client receives when it offers no OPT record at all, so raising it hands the client nothing it could not already take. Carrying no size is what made an allowed answer over 512 octets return truncated, and since the stub then retries over TCP, which is closed while contained, a name with many addresses stopped resolving altogether. It SHALL answer every other query locally with REFUSED, carrying the query's ID and question and no records. A datagram that is not a single well-formed query SHALL be neither forwarded nor answered, and DNS over TCP SHALL not be resolved: a session is refused when it starts, and one opened before the host was contained is closed on its next query. A containment whose lifeline names no host name resolves nothing. The filter's lifeline allows DNS so the agent can resolve the server, to the host's configured resolvers alone, and every lookup on a host whose DNS proxy is running passes through this proxy. The two restrictions are separate and only the filter's holds unconditionally: the proxy restricts which names resolve, and a host whose DNS proxy is disabled or stopped resolves any name its configured resolvers answer. A host that is not contained SHALL have its DNS forwarded as before.

#### Scenario: The server's name still resolves

- **GIVEN** a contained host whose lifeline names the EDR server's host name
- **WHEN** a query for that name arrives, in any letter case
- **THEN** the proxy forwards it

#### Scenario: An allowed lookup carries only its question

- **GIVEN** a contained host whose lifeline names the EDR server's host name
- **WHEN** a query for that name arrives carrying anything after its question other than a lone minimal OPT record, such as a second record, an OPT record carrying options or flags, or stray bytes
- **THEN** the proxy forwards the query's header and question alone, with no records

#### Scenario: An allowed lookup keeps a rebuilt UDP size

- **GIVEN** a contained host whose lifeline names the EDR server's host name
- **WHEN** a query for that name arrives offering a UDP payload size in an OPT record that carries nothing else
- **THEN** the proxy forwards the query with an OPT record of its own, holding the offered size clamped to between 512 and 1232 and nothing else
- **AND** an OPT record carrying an option, an unknown version, an extended response code, the DNSSEC-OK bit or any other flag leaves the forwarded query with no record at all

#### Scenario: Any other name is refused locally

- **GIVEN** a contained host
- **WHEN** a query for any other name arrives
- **THEN** the proxy answers REFUSED with the query's ID and question and no records, and forwards nothing

### Requirement: Containment state is persisted and ordered

The network extension SHALL persist an accepted containment update before applying it, and SHALL apply the persisted state as the first settings of a starting content filter, so a contained host is contained again when the extension restarts and never passes through the uncontained settings while doing so. Updates SHALL be ordered by epoch, then version; an update that is not newer SHALL be refused, except that an update at the same epoch and version that changes only the lifeline SHALL be accepted, so the lifeline of a contained host can be refreshed. The lifeline here means the server endpoint AND the set of operator-chosen destinations the host may still reach, because that set changes without any host's containment state changing: an update carrying a different set at the same epoch and version would otherwise be refused and the change reported as delivered. A containment that names no usable lifeline (no address, an address that is not an IPv4 or IPv6 literal or is the unspecified address, more than 16 addresses, a port outside 1 to 65535, or a name that is not a DNS host name, or more than 4 names) SHALL be refused whole, leaving the current state in force.

#### Scenario: Containment survives an extension restart

- **GIVEN** a containment update the extension accepted
- **WHEN** the extension restarts
- **THEN** it loads that containment and applies it as the filter's first settings

#### Scenario: An older update is refused

- **GIVEN** a containment at a given epoch and version
- **WHEN** an update arrives with a lower epoch, or the same epoch and a lower version
- **THEN** it is refused and the current state stays in force

#### Scenario: A lifeline refresh at the same version is accepted

- **GIVEN** a contained host
- **WHEN** an update arrives at the same epoch and version naming different server addresses, or naming a different set of destinations the host may still reach
- **THEN** it is accepted and the new lifeline takes effect
- **AND** an update carrying the same server addresses and the same set is still refused

#### Scenario: A containment without a usable lifeline is refused

- **GIVEN** any current state
- **WHEN** a containment update arrives with no server addresses, an address that is not an IP literal, the unspecified address, or a port outside 1 to 65535
- **THEN** it is refused and the current state stays in force

### Requirement: The extension reports containment status

The network extension SHALL report its containment status to the agent as an `ne_containment_status` control event describing the state it holds: whether the host is contained, that state's version and epoch, whether the content filter was confirmed to enforce that state, the server addresses of the lifeline that filter was confirmed to enforce, the version of the reachable-address set it was confirmed to enforce, and the error when the latest attempt to apply it failed or found no content filter running. The lifeline addresses SHALL be absent when no state is confirmed. They are what tells one lifeline from another, because a refresh carries the same version and epoch and changes only the addresses, so without them the agent cannot know which lifeline the filter holds. The reachable-set version is reported for the same reason and a sharper one: a change to that set reuses the containment version and epoch, so a status describing the previous set is otherwise indistinguishable from one describing the new one, and an agent waiting for such a change to be applied would accept the older status as its confirmation and report a success the host is not enforcing. A held state waiting behind an apply in flight, being applied to a content filter that has just started, or waiting for the content filter to start after the extension starts, SHALL be reported as not applied with no error. A state is reported applied only when the running filter was confirmed to enforce it: an earlier state that was applied SHALL NOT be reported in its place, and neither a failed attempt nor the running filter stopping SHALL leave an earlier confirmation standing. It SHALL report after every change and whenever an agent completes the hello handshake, including before the content filter has started. A host that has never received a containment update SHALL send no status. Filter settings SHALL be applied one at a time, so a later update never takes effect before an earlier one, and a result from a filter that has since stopped SHALL NOT be reported.

#### Scenario: The status names the lifeline the filter enforces

- **GIVEN** a contained host whose content filter was confirmed to enforce a lifeline
- **WHEN** the extension reports its status
- **THEN** the status names that lifeline's server addresses
- **AND** a status for a state no filter is confirmed to enforce names none

#### Scenario: The status says whether containment was applied

- **GIVEN** the extension has applied, or failed to apply, a containment
- **WHEN** it reports its status
- **THEN** the event carries contained, version, epoch, applied and, on failure, the error

#### Scenario: Updates in quick succession apply in order

- **GIVEN** filter settings are being applied for one containment update
- **WHEN** a newer update is accepted before that apply completes
- **THEN** the newer settings are applied after it, and only the newer state is reported

#### Scenario: A stopped filter's result is not reported

- **GIVEN** filter settings are being applied to a content filter
- **WHEN** that filter stops and a replacement starts before the apply completes
- **THEN** the completed apply is not reported, and the replacement is given the current state

#### Scenario: A failed apply is not reported as applied

- **GIVEN** a running filter was confirmed to enforce the held state
- **WHEN** a later attempt to apply that state fails, or finds no content filter running
- **THEN** the status names the state as not applied, with the failure as its error

#### Scenario: A state waiting to be applied is reported as pending

- **GIVEN** the extension holds a containment update whose filter settings have not yet been confirmed
- **WHEN** it reports its status
- **THEN** the status names that update's version as not applied, with no error
