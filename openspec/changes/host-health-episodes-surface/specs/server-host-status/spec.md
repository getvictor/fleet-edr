## MODIFIED Requirements

### Requirement: The host API surfaces per-host health

An operator holding host read access SHALL see each host's overall health status in the host list, and SHALL see the full list of component conditions in the single-host detail. A host without a stored snapshot SHALL appear in the list with overall status `unknown` rather than being omitted.

The single-host detail SHALL also report the host's recorded sensor faults: the newest still open, then the most recently resolved, open ones first so a fault that still needs someone is not buried beneath resolved history. Each SHALL carry the part at fault, the fault's own detail, its severity, when it began on the host, and for a resolved fault when it ended. The detail SHALL report them for a host that has never posted a snapshot, because a fault and a snapshot are recorded independently. Each half of the list SHALL be bounded, including the open half: a fault recorded by an agent too old to name its component can never close, and one host can accumulate them.

The overall health status SHALL NOT be raised by a recorded fault. It says whether the host is healthy now, and while a fault is live the component reporting it is already unhealthy. Raising it for an open fault would add nothing then, and would leave a recovered host looking broken forever once a fault that can never close had been recorded.

The change from the prior requirement is the single-host detail reporting recorded sensor faults alongside the component conditions.

#### Scenario: The host list carries the overall status

- **GIVEN** an operator with host read access and a host with a stored snapshot
- **WHEN** they read the host list
- **THEN** the host's row carries its computed overall health status

#### Scenario: The host detail carries the component conditions

- **GIVEN** an operator with host read access and a host with a stored snapshot
- **WHEN** they read that host's detail
- **THEN** the response carries each component's type, status, reason, message, and last-transition timestamp

#### Scenario: A host with no snapshot still lists with unknown health

- **GIVEN** a host that has sent events but never posted a snapshot
- **WHEN** an operator reads the host list
- **THEN** the host appears with overall status `unknown`

#### Scenario: The detail reports recorded sensor faults

- **GIVEN** an operator with host read access and a host with an open sensor fault and a resolved one
- **WHEN** they read that host's detail
- **THEN** the response lists the open fault before the resolved one, each with the part at fault, its detail, and when it began
- **AND** the resolved fault carries when it ended
- **AND** the overall health status is the one the host's snapshot reports, not raised by either fault

#### Scenario: A host with no snapshot still reports its recorded faults

- **GIVEN** a host with a recorded sensor fault that has never posted a snapshot
- **WHEN** an operator reads that host's detail
- **THEN** the overall status is `unknown` and the fault is still reported
