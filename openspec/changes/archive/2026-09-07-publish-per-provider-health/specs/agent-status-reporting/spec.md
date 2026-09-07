# Agent status reporting: per-provider capture health delta

## ADDED Requirements

### Requirement: The agent reports each capture provider as its own component

The agent SHALL report the state of each capture provider the extension reports to it as its own component in the status snapshot, in addition to the existing single component for the extension that owns them.

The collapsed component cannot carry this. It reports the worst state among the providers, so a host whose providers are all capturing and a host with one wedged provider are indistinguishable to any reader of the snapshot. The server needs each provider's state as a POSITIVE claim, because the only way to detect a provider that has stopped delivering while believing itself healthy is to contradict its own claim against the telemetry that actually arrived.

A provider the extension does NOT report SHALL NOT appear in the snapshot, and one that stops being reported SHALL be removed from it. The extension reports a deliberate operator opt-out by omitting the provider, so a retained component would publish a positive claim for a provider that is switched off. That is worse than reporting nothing: a consumer that contradicts these claims against arriving telemetry would report a fault on a provider that is simply not running by choice.

A provider whose reported state is unchanged SHALL keep the instant at which it entered that state. Liveness reports arrive on every extension handshake, so re-stamping each time would report every provider as having just changed.

A provider state the agent does not recognise SHALL be reported as unknown rather than as running or stopped, so that a newer extension's vocabulary neither manufactures a claim that can be contradicted nor condemns the host.

A liveness report the agent could not READ SHALL leave the provider view unchanged. An unreadable report is indistinguishable by value from the extension reporting that no provider is running, since both present as an empty set, so acting on it would clear every provider and the next readable report would re-add them as though each had just changed. A readable report carrying no providers is different and SHALL clear them, because that is the extension stating that nothing is capturing.

The provider components SHALL be ordered stably across reports, since the server replaces its stored snapshot last-writer-wins and an unstable order would present an unchanged report as a change.

#### Scenario: Each reported provider appears as its own component

- **GIVEN** an extension reporting one provider capturing and another stopped
- **WHEN** the agent posts its status snapshot
- **THEN** the snapshot carries a component for each provider, naming its own state
- **AND** the snapshot still carries the component for the extension that owns them

#### Scenario: A provider the extension stops reporting is dropped

- **GIVEN** a snapshot carrying a component for an optional provider
- **WHEN** the operator disables that provider and the extension stops reporting it
- **THEN** the next snapshot does not carry a component for it
- **AND** the extension's own component is not degraded by its absence

#### Scenario: An unchanged provider keeps its transition instant

- **GIVEN** a provider reported in the same state across several liveness reports
- **WHEN** the agent posts each snapshot
- **THEN** the provider's component reports the instant it entered that state, not the time of the latest report

#### Scenario: A report the agent could not read leaves the provider view untouched

- **GIVEN** a snapshot carrying components for two running providers
- **WHEN** the agent receives a liveness report whose payload it cannot read
- **THEN** the provider components are unchanged, including the instants they carry
- **AND** a readable report carrying no providers does clear them

#### Scenario: An unrecognised provider state is reported as unknown

- **GIVEN** an extension reporting a provider state this agent does not recognise
- **WHEN** the agent posts its status snapshot
- **THEN** the provider's component reports unknown
- **AND** the component still identifies the provider
