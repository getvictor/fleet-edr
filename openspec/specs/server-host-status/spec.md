# server-host-status Specification

## Purpose

The server accepts a host-token-authenticated status check-in, persists the latest health snapshot per host as last-writer-wins, and validates component status against a closed set while storing unrecognized component types and reasons verbatim, so an operator can see current per-host agent and extension health.

## Requirements

### Requirement: The server accepts and persists a host status snapshot

The server SHALL expose a host-token-authenticated check-in that accepts a status snapshot carrying the agent version and a list of component conditions, and SHALL persist the latest snapshot per host as last-writer-wins keyed on the host. A snapshot from an unauthenticated or invalidly-authenticated caller SHALL be rejected. The server SHALL validate the component status against the closed set `healthy`, `degraded`, `unhealthy`, `unknown` and reject a snapshot carrying any other status value, while accepting component `type` and `reason` values it does not recognize and storing them verbatim.

#### Scenario: A valid snapshot is stored as the latest health for the host

- **GIVEN** an enrolled host with a valid host token
- **WHEN** it posts a snapshot with two components
- **THEN** the server stores that snapshot as the host's current health

#### Scenario: A later snapshot replaces an earlier one

- **GIVEN** a host that has already posted a snapshot
- **WHEN** it posts a newer snapshot for the same host
- **THEN** the server's stored health reflects the newer snapshot and not the earlier one

#### Scenario: An unknown component type is stored verbatim

- **GIVEN** a valid host token
- **WHEN** the host posts a snapshot containing a component whose type the server does not recognize but whose status is in the closed set
- **THEN** the snapshot is accepted and the unknown component is stored and returned unchanged

#### Scenario: An invalid status value is rejected

- **WHEN** a host posts a snapshot whose component status is not in the closed set
- **THEN** the server rejects the snapshot and stores nothing

#### Scenario: An unauthenticated check-in is rejected

- **WHEN** a caller posts a snapshot without a valid host token
- **THEN** the server rejects the request and stores nothing

### Requirement: The server computes an overall host-health rollup

The server SHALL derive an overall health status for each host from its component conditions as the worst condition present: `unhealthy` if any component is unhealthy, otherwise `degraded` if any component is degraded, otherwise `healthy` if at least one component is present, otherwise `unknown`. The agent SHALL NOT supply the overall status; it is computed on the server from the stored components.

#### Scenario: One unhealthy component makes the host unhealthy

- **GIVEN** a host whose network extension is healthy and whose security extension is unhealthy
- **WHEN** the rollup is computed
- **THEN** the host's overall status is `unhealthy`

#### Scenario: A host with no snapshot rolls up to unknown

- **GIVEN** a host that has never posted a snapshot
- **WHEN** the host's overall status is read
- **THEN** it is `unknown`

#### Scenario: All-healthy components roll up to healthy

- **GIVEN** a host whose every component is healthy
- **WHEN** the rollup is computed
- **THEN** the host's overall status is `healthy`

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

### Requirement: Server persists inventory from the status check-in

When an accepted status report carries a host inventory block, the server SHALL persist the reported hostname, OS product name, OS product version, OS build, and the report's agent version onto the host's identity record, together with the report's timestamp, so the identity record reflects the latest check-in rather than the enrollment-time snapshot. A status report that carries no inventory block MUST leave the identity record untouched, and an empty field inside a present inventory block MUST preserve the previously recorded value rather than overwrite it (an empty claim means the agent's source was unavailable, and a degraded collector must not blank known identity). Inventory persistence MUST NOT change the health snapshot semantics: a report with invalid component status is rejected as a whole, including its inventory.

#### Scenario: Check-in refreshes identity after an OS upgrade

- **GIVEN** an enrolled host whose enrollment recorded OS version `26.3`
- **WHEN** the agent posts a status report whose inventory carries OS version `26.4`
- **THEN** the host's identity record reports OS version `26.4` without a re-enrollment

#### Scenario: Report without inventory leaves identity untouched

- **GIVEN** an enrolled host with recorded identity fields
- **WHEN** an agent posts a status report that omits the inventory block (an older agent)
- **THEN** the report's health snapshot is stored
- **AND** the identity record is unchanged

#### Scenario: Empty inventory fields preserve recorded identity

- **GIVEN** an enrolled host whose identity record holds OS version `26.4` from a prior check-in
- **WHEN** the agent posts a status report whose inventory carries a non-empty hostname but empty OS fields (a degraded collector)
- **THEN** the hostname is refreshed
- **AND** the recorded OS fields are preserved, not blanked

#### Scenario: Rejected report does not write inventory

- **GIVEN** a status report whose component snapshot carries an invalid status value and whose inventory carries a new hostname
- **WHEN** the server processes the report
- **THEN** the report is rejected
- **AND** the identity record is unchanged

### Requirement: The server derives health conditions its endpoints cannot report

The system SHALL derive per-host health conditions by contradicting what a host claims about its capture providers against the telemetry that reached the server, so that a provider which has stopped delivering while continuing to report itself healthy is surfaced as degraded rather than healthy.

A derived condition SHALL be raised for a capture provider when all of the following hold, and SHALL NOT be raised otherwise:

- the host claims that provider is capturing, which is a claim only its own reported condition can make;
- the host produced process telemetry inside the silence window, so the host is known to be doing work rather than idle;
- that provider's stream produced nothing inside the silence window.

The silence window SHALL be 2 hours, measured back from the time of the read and inclusive of its start instant. It SHALL NOT include events stamped after the time of the read, so that a host with a skewed clock cannot mask a fault.

The gate is the provider's OWN claim, not the host's overall health. A host reporting an unrelated component as faulty SHALL still have its capturing providers checked, and a provider the host already reports as stopped SHALL NOT gain a second, derived condition for the same fault.

A host that claims nothing about a provider SHALL produce no condition for it. This covers a provider the operator disabled, which the agent reports either by omitting it or as its own component saying it is switched off, and a provider whose reported state the agent did not recognise. A component reporting a provider switched off SHALL NOT be read as a claim to be capturing, even though it is not a fault and reports healthy: deriving a telemetry-loss condition from the silence of a provider nobody expects to speak would report a permanent fault on every host running the supported opt-out (issue #1078). A snapshot whose components cannot be read SHALL be treated as claiming nothing.

That last rule is also the residual risk of gating on a claim, and it is recorded here rather than left implicit: a host claiming nothing is not accusable by this check, whereas inferring use from history would still have reported it. The risk is bounded by the endpoint's own reporting rules rather than by this requirement. An agent that observes no running provider reports the owning extension as unhealthy, not healthy, so an honest agent cannot present a healthy extension alongside no provider claims; that state is already surfaced by the extension's own condition. Two shapes remain. An agent predating per-provider reporting loses this detection until it is upgraded, which is accepted because the detection has never shipped without it. And a falsified snapshot is outside what a server-side inference can adjudicate at all: an endpoint able to suppress its own claims can equally fabricate the telemetry this check reads, so no gate chosen here would survive it.

A derived condition SHALL name the provider an operator must remediate, SHALL carry status `degraded` rather than `unhealthy` (it is inferred from absence, not observed by the endpoint), and SHALL be reported separately from the conditions the agent itself reported, so an operator can tell the server's inference from the endpoint's claim.

The host's effective overall status SHALL fold derived conditions in, and SHALL be the same on the host list and the host detail, so the two surfaces cannot disagree about one host. Folding SHALL NOT downgrade a worse reported status.

Derived conditions SHALL carry no last-transition timestamp, because a count over a window cannot recover the instant a stream fell silent.

A failure to read the telemetry SHALL degrade to serving the reported health alone rather than failing the request, so that losing the event archive does not take the operator's host views down with it.

#### Scenario: A wedged provider is surfaced as degraded

- **GIVEN** a host claiming its DNS proxy is capturing
- **AND** the host produced process telemetry within the silence window
- **AND** the host produced no `dns_query` events within the silence window
- **WHEN** an operator reads that host's health detail
- **THEN** the response carries a derived condition naming the DNS proxy with status `degraded`
- **AND** the host's effective overall status is `degraded`
- **AND** the conditions the agent reported are still carried unchanged alongside it

#### Scenario: An idle host is not accused

- **GIVEN** a host claiming its providers are capturing
- **AND** the host produced no process telemetry within the silence window
- **WHEN** an operator reads that host's health detail
- **THEN** no derived condition is raised
- **AND** the host's effective overall status is its reported status

#### Scenario: A provider the host does not claim is not accused

- **GIVEN** a host that reports no condition for one of its capture providers
- **AND** the host produced process telemetry within the silence window
- **AND** that provider's stream produced nothing within the silence window
- **WHEN** an operator reads that host's health detail
- **THEN** no derived condition is raised for that provider

#### Scenario: A host already reporting a fault gains no second condition

- **GIVEN** a host that reports one of its capture providers as stopped
- **WHEN** an operator reads that host's health detail
- **THEN** no derived condition is raised for that provider
- **AND** a different provider the host still claims is capturing is checked as usual

#### Scenario: The host list badge agrees with the host detail

- **GIVEN** a host for which a derived condition is raised
- **WHEN** an operator reads the host list
- **THEN** that host's row carries the same effective overall status the host detail reports

#### Scenario: The signal clears when telemetry resumes

- **GIVEN** a host previously surfaced as degraded by a derived condition
- **WHEN** the stream produces events again within the silence window
- **AND** an operator reads that host's health detail
- **THEN** no derived condition is raised
- **AND** the host's effective overall status is its reported status

#### Scenario: An unreadable archive degrades rather than failing the request

- **GIVEN** a host with a stored health snapshot
- **AND** the telemetry read fails
- **WHEN** an operator reads that host's health detail or the host list
- **THEN** the request succeeds carrying the reported health alone
- **AND** no derived condition is raised

### Requirement: A host that is not taking commands is reported as such

Where commands issued to a host have aged out without ever reaching it, the system SHALL report that on the host's health rather than leaving it discoverable only by reading the command records.

The condition SHALL be derived from the command records the system already keeps, not written by a new health reporter. A command that aged out is a command that waited its entire delivery window with no agent claiming it, so the record already carries the evidence, and a separate reporter would be a second source of truth for a fact the first one already holds.

The condition SHALL rest only on commands that aged out, and SHALL NOT rest on commands still awaiting delivery. A command queued against a host that is merely asleep or offline is the ordinary case and is not evidence of anything; a condition resting on it would fire across most of a normal fleet and stop being read.

It SHALL be reported as degraded rather than unhealthy. The expiries are certain but the conclusion that the host is at fault is an inference: a machine powered off for two days accumulates them with nothing wrong. Unhealthy remains reserved for a fault the endpoint observed directly and reported itself.

The condition SHALL carry the instant of the most recent expiry, so a reader can tell how fresh the evidence is. This differs from conditions inferred from an absence of telemetry, which have no observed instant to offer and correctly carry none; an expiry is an observed event with a recorded time.

It SHALL be reflected in the host's overall status and not only in its component list. The failure this exists for is one where the header read healthy while the operator's command did nothing, so a condition reachable only by expanding a panel would not address it.

The condition SHALL be evaluated for every host, and SHALL NOT be restricted to hosts that claim to be capturing telemetry. Command deliverability does not depend on any such claim, and a host that claims nothing while also taking nothing is precisely a host worth reporting.

Where the command records cannot be read, the system SHALL omit the condition and SHALL still serve the host's health. One supplementary condition failing is not a reason to fail the page an operator uses to diagnose.

#### Scenario: Commands that aged out undelivered raise a condition

- **GIVEN** a host whose issued commands aged out without any agent claiming them
- **WHEN** its health is read
- **THEN** a degraded condition reports that the host is not taking commands
- **AND** the condition carries how many aged out and when the most recent one did
- **AND** the host's overall status reflects it rather than reading healthy

#### Scenario: Commands still awaiting delivery raise nothing

- **GIVEN** a host with commands queued but none yet aged out
- **WHEN** its health is read
- **THEN** no such condition is reported, because an offline host with queued work is the ordinary case

### Requirement: The server records host health episodes

A component's health is level state: it reports what is true now and is overwritten as soon as that changes. That is the right shape for a console badge and the wrong shape for accountability, because a host that stopped capturing and was later fixed by hand reads healthy afterwards and leaves no record that it was ever blind, or for how long. The system SHALL persist a health EPISODE for a component fault that requires a person to act, independently of the level state that reports it.

An episode SHALL identify the host and the component it concerns, SHALL name the kind of fault, and SHALL record when it began. It SHALL carry the fault's own machine-readable detail, so an operator reading the record does not have to parse prose to learn which component to act on.

Where a component owns several independently failing parts, the episode SHALL also name WHICH part is at fault. Two parts failing under one component are two outages and SHALL be recorded as two episodes, each keeping its own detail.

A report that cannot name the component SHALL still be recorded, because it names a host that is not capturing and that is what an operator has to act on. Such an episode has nothing to close it and stays open: reporting a fault we cannot tie to a component is honest, and inventing a component to make it resolvable would not be.

An episode's opening and closing instants SHALL both be observed on the host rather than taken from the server's clock. The interval between them is what the record exists to provide, so measuring one end by when the server processed a report would count queue backlog and delivery delay as part of the outage. An episode SHALL NOT close before it opened, whatever the reporting host's clock does between the two reports.

An episode SHALL be closed when the component it concerns reports healthy again, recording the instant it closed. An episode that has not closed SHALL be distinguishable from one that has, so "this host is not capturing now" and "this host was not capturing for eleven hours last week" are separate answers drawn from the same record.

An episode SHALL be identified by the occurrence it records, so that recording the same occurrence again changes nothing. A fault is reported once per outage, and the repetition the system actually sees is REDELIVERY of that one report: delivery is at-least-once, so a report can be processed, acknowledged poorly, and processed again. Recording SHALL therefore collapse on the occurrence whether or not the episode has closed in between, and a later outage SHALL open its own episode because it is its own occurrence.

Identifying an episode by "a fault of this kind is open for this component" instead is NOT sufficient, and is worth stating because it is the obvious design and it is wrong here: the key stops matching the moment the episode closes, so a redelivery arriving after a recovery records the same outage a second time.

A component reporting healthy when no episode is open SHALL be accepted and change nothing. A host reporting healthy for a component it has never reported a fault for is the overwhelmingly common case and is not an error.

#### Scenario: A fault that needs a person opens an episode

- **GIVEN** a host whose capture provider stopped and whose agent reports that its repair attempts are exhausted
- **WHEN** the server records the failure
- **THEN** an open episode exists for that host and component, naming the fault kind and the instant it began
- **AND** the instant it began is the one observed on the host, not when the server processed the report
- **AND** the episode carries the provider, the outcome, and the number of repairs attempted as fields rather than as prose

#### Scenario: Two parts of one component failing are two episodes

- **GIVEN** a host where two capture providers owned by the same component have each exhausted recovery
- **WHEN** the server records both failures
- **THEN** each has its own open episode carrying its own provider, outcome, and attempt count
- **AND** the component recovering closes both, because the component is what an operator restores

#### Scenario: A fault whose component cannot be named is still recorded

- **GIVEN** a report of an exhausted repair that does not name the component the provider belongs to
- **WHEN** the server records the failure
- **THEN** an episode is recorded for that host
- **AND** it remains open, because no component recovery can be matched to it

#### Scenario: A redelivered report does not open a second episode

- **GIVEN** a host with an episode recorded for a reported fault
- **WHEN** the same report is delivered and processed again
- **THEN** the recorded episode is unchanged and no second episode is opened
- **AND** this holds whether that episode is still open or has already closed

#### Scenario: An episode closes when the component recovers

- **GIVEN** a host with an open episode for a component
- **WHEN** that host's status check-in reports the component healthy
- **THEN** the episode is closed, recording the instant the component was observed healthy on the host
- **AND** the record reports how long the component was in fault
- **AND** a check-in too old to update the host's current health does not close the episode either

#### Scenario: Recovery with no open episode is not an error

- **GIVEN** a host with no open episode for a component
- **WHEN** that host's status check-in reports the component healthy
- **THEN** the check-in succeeds and no episode is created or modified
