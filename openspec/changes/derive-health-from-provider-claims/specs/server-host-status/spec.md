# server-host-status delta: derive from the provider's own claim

## MODIFIED Requirements

### Requirement: The server derives health conditions its endpoints cannot report

The system SHALL derive per-host health conditions by contradicting what a host claims about its capture providers against the telemetry that reached the server, so that a provider which has stopped delivering while continuing to report itself healthy is surfaced as degraded rather than healthy.

A derived condition SHALL be raised for a capture provider when all of the following hold, and SHALL NOT be raised otherwise:

- the host claims that provider is capturing, which is a claim only its own reported condition can make;
- the host produced process telemetry inside the silence window, so the host is known to be doing work rather than idle;
- that provider's stream produced nothing inside the silence window.

The silence window SHALL be 2 hours, measured back from the time of the read and inclusive of its start instant. It SHALL NOT include events stamped after the time of the read, so that a host with a skewed clock cannot mask a fault.

The gate is the provider's OWN claim, not the host's overall health. A host reporting an unrelated component as faulty SHALL still have its capturing providers checked, and a provider the host already reports as stopped SHALL NOT gain a second, derived condition for the same fault.

A host that claims nothing about a provider SHALL produce no condition for it. This covers a provider the operator disabled, which the agent reports by omitting it, and a provider whose reported state the agent did not recognise. A snapshot whose components cannot be read SHALL be treated as claiming nothing.

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
