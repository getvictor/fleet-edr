## ADDED Requirements

### Requirement: Host network containment in the console

The host page header SHALL show where the host's network containment stands: Containing while a containment has not been confirmed by the host, Contained once it has, Containment failed when the host reported it could not apply it, Releasing and Release failed likewise for a release, and nothing for a host that is not contained. While a containment or release is on its way the page SHALL re-read the state until the host confirms or fails it, and SHALL NOT poll otherwise. An operator holding `host.isolate` SHALL be offered Contain host on a host that is not contained and Release host on a contained one; the action SHALL ask for a reason (required, at most 1024 characters) in a confirmation that says what containment does before it is sent, and SHALL go through the reauthentication prompt when the session needs a recent authentication. An operator without `host.isolate` SHALL see the state without the action. The host list SHALL show the same badge on each host that has one. For a contained host whose live health says its DNS proxy may not be restricting names, the header SHALL say so, and SHALL make the explanation reachable by keyboard rather than on hover alone. It SHALL say only as much as its evidence supports: a host reporting the proxy switched off is stated as such, while the server having seen no DNS capture arrive during otherwise ordinary reporting SHALL be put as what it is, evidence that names may not be restricted, since the server grades that inference degraded rather than a fault because a skewed clock or an ingest backlog explain silence too. Where both are present the host's own report SHALL be preferred, being the definite one. It SHALL be read from the host's health rather than from the containment command's result, which is fixed once that command completes and so cannot reflect a proxy that stopped afterwards. A host whose health has not been read SHALL NOT be shown as unfiltered, and neither SHALL a host whose containment is still on its way, which is not yet contained. A proxy reported stopped by a fault SHALL NOT be repeated here, since the health section reports it as the fault it is.

#### Scenario: A contained host whose names are not filtered says so

- **GIVEN** a contained host whose health says its DNS proxy is disabled
- **WHEN** an operator opens its page
- **THEN** the header says its DNS is restricted by destination only, and the explanation can be reached with a keyboard
- **AND** a host whose only evidence is the server having seen no DNS capture is told that instead, as something that may be so rather than as a finding
- **AND** a host whose proxy is capturing, whose health is unread, or whose containment is still on its way says nothing of the kind

#### Scenario: An operator contains a host from its page

- **GIVEN** an operator holding `host.isolate` on the page of a host that is not contained
- **WHEN** they choose Contain host, give a reason and confirm
- **THEN** the containment is requested with that reason, the header shows Containing, and it shows Contained once the host confirms it

#### Scenario: A contained host can be released

- **GIVEN** an operator holding `host.isolate` on the page of a contained host
- **WHEN** they choose Release host, give a reason and confirm
- **THEN** the release is requested with that reason and the header shows Releasing

#### Scenario: Without host.isolate the state is shown and the action is not

- **GIVEN** an operator without `host.isolate` on the page of a contained host
- **WHEN** the page loads
- **THEN** the header shows Contained and offers neither Contain host nor Release host

#### Scenario: The host list marks hosts under containment

- **GIVEN** a contained host, a host whose containment is on its way, and a released host
- **WHEN** the operator opens the hosts page
- **THEN** the first shows Contained, the second Containing, and the released host shows no containment badge
