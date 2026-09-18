## MODIFIED Requirements

### Requirement: EDR sensor tamper detection

Disabling security tooling is a recognised technique, and the product has never detected it being used against itself. The system SHALL register a `sensor_tamper` rule that raises a finding when one of the EDR's own capture providers stops.

The finding SHALL carry no ATT&CK technique. The rule reports a provider that stopped and did not come back, and a crash produces that state identically, so it cannot observe the actor that Impair Defenses names. Deciding that is the ATT&CK attribution sweep's, and it is stated here rather than left for the sweep's delta alone, because a requirement mandating the technique would archive alongside the one forbidding it and leave the canonical spec contradicting itself.

The rule SHALL be evaluated against the durable capture-provider transition records rather than against agent health. Health is level state, and the agent repairs a stopped provider automatically, so by the time an analyst looks the health view reports the host healthy and no trace remains that capture was ever off.

A stop SHALL NOT produce a finding when capture for the same provider resumes within a short recovery window. This is what separates a routine agent upgrade from tampering: replacing the system extension stops its providers, and the platform reports the same stop reason for that as for somebody switching capture off, so the reason cannot be the discriminator. The replacement provider resumes about a second later, whereas a stop that needed the agent's repair takes tens of seconds. The rule MUST NOT decide on the platform's stop reason.

The rule SHALL NOT conclude that capture failed to resume until the recovery window has elapsed, because a resumption inside the window has to reach the server before it can be observed. An undecided stop SHALL be re-evaluated rather than reported early, and the wait SHALL be bounded so a stop whose recovery never arrives is still reported.

A finding SHALL cite the stop it fired on and SHALL identify the provider, so an analyst can tell which telemetry stream the host stopped reporting. Repeated evaluation of one stop SHALL collapse to a single alert, while a separate stop SHALL raise its own.

A provider an operator has deliberately disabled SHALL NOT produce a finding, and the rule SHALL need no suppression list to achieve it. The agent reports a supported opt-out as the provider being `disabled` rather than stopped, or omits the provider entirely on an extension predating that report, and records a transition for neither, so no stop record for that provider reaches the rule at all.

The rule reports that capture stopped, NOT whether it was later restored. Whether the repair succeeded, is still pending, or gave up is carried by the subsequent transition records, and none of it is known at the time the stop must be reported. Gating the finding on the outcome would suppress the most serious case, a provider that never comes back at all.

#### Scenario: A capture provider stops and does not resume

- **GIVEN** a host reporting a capture provider running
- **WHEN** that provider stops and capture does not resume within the recovery window
- **THEN** the engine produces one `sensor_tamper` finding
- **AND** that finding carries no ATT&CK technique
- **AND** the finding names the provider and cites the stop record

#### Scenario: An upgrade cutover does not fire

- **GIVEN** a capture provider that stops while the agent's system extension is being replaced
- **AND** the stop carries the same platform reason a deliberate disable carries
- **WHEN** capture for that provider resumes within the recovery window
- **THEN** the engine produces no `sensor_tamper` finding

#### Scenario: A stop is not judged before its recovery window elapses

- **GIVEN** a stop record that reaches the engine before its recovery window has elapsed
- **WHEN** the engine evaluates it and finds no resumption yet
- **THEN** the engine does not produce a finding for it yet and re-evaluates it later
- **AND** the engine reports the stop once the window has elapsed with no resumption

#### Scenario: A deliberately disabled provider does not fire

- **GIVEN** an operator has disabled an optional capture provider
- **WHEN** the agent reports its providers, naming that provider `disabled`
- **THEN** no stop record exists for that provider and the engine produces no `sensor_tamper` finding
