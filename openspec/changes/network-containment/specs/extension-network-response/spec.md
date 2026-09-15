## ADDED Requirements

### Requirement: Containment is enforced by the operating system

The network extension SHALL enforce host network containment as content-filter settings whose default action drops every flow the lifeline does not allow, so the operating system enforces it without consulting the provider: new and established connections to other destinations are cut, and containment stays in force while the provider is stopped or restarting. A contained host SHALL keep a lifeline of TCP to each EDR server address it was given on the server port, DHCP between the client and server ports (UDP 68 to 67, and UDP 546 to 547 for DHCPv6), and outbound DNS (TCP and UDP 53); loopback is not filtered. A host that is not contained SHALL have the filter's telemetry settings, which hand every flow to the provider, except that a release SHALL keep TCP to the released containment's EDR server endpoint, and to the endpoint a lifeline refresh last replaced since the content filter started, allowed by rule until the content filter next starts. The lifeline rules decide the connections the agent opens while the host is contained, so the provider never sees them, and the operating system cuts such a connection once it is handed to a provider that never saw it, together with the release command's outcome on its way to the server. The kept server flows record no `network_connect` events.

#### Scenario: A contained host keeps only the lifeline

- **GIVEN** a containment naming an EDR server address and port
- **WHEN** the extension builds the filter rules for it
- **THEN** the rules allow TCP to that address on that port, DHCP from the client port to the server port, and DNS, and nothing else

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

While the host is contained, the network extension's DNS proxy SHALL forward a DNS query only when it is a single-question query for one of the lifeline's names, compared case-insensitively and without a trailing dot label by label, and SHALL send it only to one of the host's configured resolvers: the one the client addressed when it is configured, otherwise the first configured one, with the answer still returned as if from the resolver the client addressed. It SHALL answer every other query locally with REFUSED, carrying the query's ID and question and no records, as it does an allowed query on a host with no configured resolver. A datagram that is not a single well-formed query SHALL be neither forwarded nor answered, and DNS over TCP SHALL not be resolved: a session is refused when it starts, and one opened before the host was contained is closed on its next query. A containment whose lifeline names no host name resolves nothing. The filter's lifeline allows DNS so the agent can resolve the server, and every lookup on the host passes through this proxy, so this is what keeps DNS from carrying traffic out of a contained host. A host that is not contained SHALL have its DNS forwarded as before.

#### Scenario: The server's name still resolves

- **GIVEN** a contained host whose lifeline names the EDR server's host name
- **WHEN** a query for that name arrives, in any letter case
- **THEN** the proxy forwards it

#### Scenario: An allowed lookup goes to a configured resolver

- **GIVEN** a contained host whose lifeline names the EDR server's host name
- **WHEN** a query for that name is addressed to a resolver that is not one of the host's configured resolvers
- **THEN** the proxy sends it to a configured resolver instead, and nothing to the address the client chose

#### Scenario: Any other name is refused locally

- **GIVEN** a contained host
- **WHEN** a query for any other name arrives
- **THEN** the proxy answers REFUSED with the query's ID and question and no records, and forwards nothing

### Requirement: Containment state is persisted and ordered

The network extension SHALL persist an accepted containment update before applying it, and SHALL apply the persisted state as the first settings of a starting content filter, so a contained host is contained again when the extension restarts and never passes through the uncontained settings while doing so. Updates SHALL be ordered by epoch, then version; an update that is not newer SHALL be refused, except that an update at the same epoch and version that changes only the server endpoint SHALL be accepted, so the lifeline of a contained host can be refreshed. A containment that names no usable lifeline (no address, an address that is not an IPv4 or IPv6 literal or is the unspecified address, more than 16 addresses, a port outside 1 to 65535, or a name that is not a DNS host name, or more than 4 names) SHALL be refused whole, leaving the current state in force.

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
- **WHEN** an update arrives at the same epoch and version naming different server addresses
- **THEN** it is accepted and the new addresses become the lifeline

#### Scenario: A containment without a usable lifeline is refused

- **GIVEN** any current state
- **WHEN** a containment update arrives with no server addresses, an address that is not an IP literal, the unspecified address, or a port outside 1 to 65535
- **THEN** it is refused and the current state stays in force

### Requirement: The extension reports containment status

The network extension SHALL report its containment status to the agent as an `ne_containment_status` control event describing the state it holds: whether the host is contained, that state's version and epoch, whether the content filter was confirmed to enforce that state, and the error when the latest attempt to apply it failed or found no content filter running. A held state waiting behind an apply in flight, being applied to a content filter that has just started, or waiting for the content filter to start after the extension starts, SHALL be reported as not applied with no error. A state is reported applied only when the running filter was confirmed to enforce it: an earlier state that was applied SHALL NOT be reported in its place, and neither a failed attempt nor the running filter stopping SHALL leave an earlier confirmation standing. It SHALL report after every change and whenever an agent completes the hello handshake, including before the content filter has started. A host that has never received a containment update SHALL send no status. Filter settings SHALL be applied one at a time, so a later update never takes effect before an earlier one, and a result from a filter that has since stopped SHALL NOT be reported.

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
