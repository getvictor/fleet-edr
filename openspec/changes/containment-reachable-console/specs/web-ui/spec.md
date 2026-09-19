## ADDED Requirements

### Requirement: Reachable destinations are edited in containment settings

Admin settings SHALL include a Containment section that shows the reachable-address set a contained host may still reach on top of containment's own lifeline, the number of destinations used out of the allowed number, and when and by whom the set was last saved. It SHALL also report how many hosts are contained or being contained, so an operator sees what a change reaches; when that count cannot be read, the section SHALL say so rather than report a count it does not have. An operator with `containment_config.write` SHALL be able to edit a draft of the whole set, and saving it SHALL require a reason and SHALL replace the set through `PUT /api/v1/containment/reachable-addresses`. Because the write is gated on a recent authentication, a save SHALL prompt for reauthentication and retry on success. The server SHALL remain the only validator of a destination: when it refuses the set, the section SHALL show the server's message and keep the draft. A save SHALL name the version the draft started from, and when the server refuses it because the set has changed since, the section SHALL say so, keep the draft, and offer to load the latest set. A contained host's page SHALL say how many destinations it can still reach when the set holds any, alongside rather than instead of any caveat about name filtering, and SHALL say nothing when the set is empty, the host is not contained, or the set cannot be read.

#### Scenario: The console shows the destinations and who they reach

- **GIVEN** a stored set with two destinations, and hosts that are contained
- **WHEN** an operator opens Containment settings
- **THEN** the section lists each destination with the port and transport it allows and the name the operator gave it
- **AND** it reports the destinations used out of the allowed number, when and by whom the set was last saved, and how many hosts are contained or being contained

#### Scenario: A count that cannot be read is not reported as a number

- **GIVEN** a stored set, and a containment list the server will not serve
- **WHEN** an operator opens Containment settings
- **THEN** the section says how many hosts the set reaches could not be read
- **AND** the set is still listed and still editable

#### Scenario: A reader cannot change the destinations

- **GIVEN** an operator with `containment_config.read` and without `containment_config.write`
- **WHEN** they open Containment settings
- **THEN** the section lists the destinations with no remove, add, discard or save controls

#### Scenario: An operator saves changed destinations with a reason

- **GIVEN** an operator with `containment_config.write` who removes one destination and adds another
- **WHEN** they save and give a reason
- **THEN** the whole edited set, the reason and the version the draft started from are sent in one replace request, and nothing is sent before the reason is given
- **AND** the section reports the version saved, and that a host contained from now on gets it with its containment while a host already contained gets it within minutes

#### Scenario: A refused destination is shown and the draft kept

- **GIVEN** a draft holding a destination the server refuses as too broad
- **WHEN** the operator saves it
- **THEN** the section shows the server's refusal, naming which rule was broken and which entry broke it
- **AND** the draft is kept for the operator to fix, and editing it clears the message

#### Scenario: A contained host says what it can still reach

- **GIVEN** a contained host, and a reachable set holding at least one destination
- **WHEN** an operator holding `containment_config.read` opens the host's page
- **THEN** the host says how many destinations it can still reach on top of its connection to the EDR server, and where to change them
- **AND** it says this alongside any caveat about name filtering rather than instead of it, because both are reasons the host is not fully cut off
- **AND** it says nothing when the set is empty, when the host is not contained yet, or when the set cannot be read, so a host that reads as fully cut off is one that is

#### Scenario: A save of an outdated set is refused

- **GIVEN** an operator editing the set loaded at one version, and another operator who has since saved a change
- **WHEN** the first operator saves
- **THEN** the server refuses it and the section says someone changed the destinations after the page loaded them
- **AND** the draft is kept, and loading the latest destinations on request replaces the draft with the other operator's set
