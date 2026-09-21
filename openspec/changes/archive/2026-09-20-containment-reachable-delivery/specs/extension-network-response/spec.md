## MODIFIED Requirements

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
