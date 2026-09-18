## ADDED Requirements

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

The network extension SHALL report its containment status to the agent as an `ne_containment_status` control event describing the state it holds: whether the host is contained, that state's version and epoch, whether the content filter was confirmed to enforce that state, the server addresses of the lifeline that filter was confirmed to enforce, and the error when the latest attempt to apply it failed or found no content filter running. The lifeline addresses SHALL be absent when no state is confirmed. They are what tells one lifeline from another, because a refresh carries the same version and epoch and changes only the addresses, so without them the agent cannot know which lifeline the filter holds. A held state waiting behind an apply in flight, being applied to a content filter that has just started, or waiting for the content filter to start after the extension starts, SHALL be reported as not applied with no error. A state is reported applied only when the running filter was confirmed to enforce it: an earlier state that was applied SHALL NOT be reported in its place, and neither a failed attempt nor the running filter stopping SHALL leave an earlier confirmation standing. It SHALL report after every change and whenever an agent completes the hello handshake, including before the content filter has started. A host that has never received a containment update SHALL send no status. Filter settings SHALL be applied one at a time, so a later update never takes effect before an earlier one, and a result from a filter that has since stopped SHALL NOT be reported.

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
