## ADDED Requirements

### Requirement: Background work is traced under a sampled root span

Work that no inbound request starts SHALL be traced under a root span that the sampling policy can classify, so its volume is set by a sampling decision rather than by how many queries and rules it runs. Each detection batch SHALL run under one root span that names the host and is sampled at the high-volume ratio, and the batch's rule-evaluation spans and database spans SHALL be its children. Each periodic sweep pass SHALL run under its own root span at full fidelity. A database query made with no active span SHALL NOT record a span, and connection housekeeping (session reset, statement prepare, row iteration) SHALL NOT be recorded as spans. Database latency metrics SHALL still record every query.

#### Scenario: A detection batch is sampled as one unit

- **GIVEN** the high-volume ratio is 0
- **WHEN** the processor claims a host batch and evaluates rules on it
- **THEN** neither the batch span nor any rule-evaluation or database span under it is exported

#### Scenario: A detection batch span names its host

- **GIVEN** a host with pending events
- **WHEN** the processor claims and evaluates a batch for that host
- **THEN** the batch root span carries the host id and the number of events claimed, and the detection evaluation runs under it

#### Scenario: A periodic sweep pass is one trace

- **WHEN** a periodic sweep pass runs
- **THEN** it is recorded as one root span named for the sweep, and a pass that fails records the error on that span

#### Scenario: A query outside any span records no span

- **GIVEN** a database query made with no active span
- **WHEN** the query runs
- **THEN** no span is recorded for it, while the same query made under a span records a query span and no housekeeping spans
