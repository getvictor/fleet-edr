## ADDED Requirements

### Requirement: A proxy the agent cannot speak is refused rather than used

The agent SHALL determine whether it can speak a configured proxy's scheme before connecting to it, and SHALL NOT open a connection to a proxy whose scheme it cannot speak. Credentials configured on a proxy address are sent to whatever host that address names, so a proxy the agent was never going to be able to use MUST NOT receive them: an operator's secret crossing the network in the clear is a cost paid before the agent discovers the setting was unusable, and no retry of an unusable setting may pay it again.

The decision SHALL be made where the agent resolves its proxy, so that every consumer reaches the same answer. The agent's HTTP traffic, its control channel, and the lifeline address a contained host is pinned to are all derived from one proxy setting, and a component deciding this for itself would leave a contained host pinned to a proxy the rest of the agent does not dial.

Resolving the agent's proxy SHALL NOT yield a proxy whose scheme it cannot speak, whatever code path assembled the configuration. A check applied only while reading the configuration file would be a convention that the next caller to construct that configuration directly can bypass unknowingly.

Where a configured proxy is refused, the agent SHALL connect directly and SHALL continue to run. An endpoint whose agent will not start is an unmonitored endpoint, which is a worse outcome than one that reports and keeps working, and the traffic concerned reaches only the agent's own configured server.

The agent SHALL report the refusal at startup, naming the setting, its scheme, and that it is connecting directly. Without that, the operator sees only connection failures and no indication that the setting they wrote is the cause.

#### Scenario: A refused proxy receives nothing

- **GIVEN** a proxy configured with a scheme the agent does not support, carrying credentials in its address
- **WHEN** the agent connects to its server, by any of its paths
- **THEN** no connection is made to the host that address names and no bytes are sent to it
- **AND** the credentials are not transmitted

#### Scenario: The operator is told which setting was refused

- **GIVEN** a proxy setting whose scheme the agent cannot speak
- **WHEN** the agent starts
- **THEN** it reports the setting's name and its scheme, and that it is connecting directly
- **AND** the agent starts and keeps running

#### Scenario: A supported proxy is unaffected

- **GIVEN** a proxy configured with a scheme the agent supports, with or without credentials
- **WHEN** the agent connects to its server
- **THEN** the proxy is used for every path as before, including the lifeline address a contained host is pinned to
