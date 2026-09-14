## ADDED Requirements

### Requirement: Containment is enforced by the operating system

The network extension SHALL enforce host network containment as content-filter settings whose default action drops every flow the lifeline does not allow, so the operating system enforces it without consulting the provider: new and established connections to other destinations are cut, and containment stays in force while the provider is stopped or restarting. A contained host SHALL keep a lifeline of TCP to each EDR server address it was given on the server port, DHCP (UDP 67, and UDP 547 for DHCPv6), and DNS (TCP and UDP 53); loopback is not filtered. A host that is not contained SHALL have the filter's telemetry settings, which hand every flow to the provider.

#### Scenario: A contained host keeps only the lifeline

- **GIVEN** a containment naming an EDR server address and port
- **WHEN** the extension builds the filter rules for it
- **THEN** the rules allow TCP to that address on that port, DHCP and DNS, and nothing else

#### Scenario: Releasing a host restores the telemetry settings

- **GIVEN** a host that is not contained
- **WHEN** the extension builds the filter rules for it
- **THEN** there are no lifeline rules, and the filter uses its telemetry settings

### Requirement: Containment state is persisted and ordered

The network extension SHALL persist an accepted containment update before applying it, and SHALL apply the persisted state as the first settings of a starting content filter, so a contained host is contained again when the extension restarts and never passes through the uncontained settings while doing so. Updates SHALL be ordered by epoch, then version; an update that is not newer SHALL be refused, except that an update at the same epoch and version that changes only the server endpoint SHALL be accepted, so the lifeline of a contained host can be refreshed. A containment that names no usable lifeline (no address, an address that is not an IPv4 or IPv6 literal or is the unspecified address, more than 16 addresses, or a port outside 1 to 65535) SHALL be refused whole, leaving the current state in force.

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

The network extension SHALL report its containment status to the agent as an `ne_containment_status` control event carrying whether the host is contained, the version and epoch of the state it holds, whether the content filter applied it, and the error when it did not. It SHALL report after every change and whenever an agent completes the hello handshake.

#### Scenario: The status says whether containment was applied

- **GIVEN** the extension has applied, or failed to apply, a containment
- **WHEN** it reports its status
- **THEN** the event carries contained, version, epoch, applied and, on failure, the error
