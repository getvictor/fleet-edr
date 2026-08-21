# server-host-status delta: a host that is not taking commands says so

## ADDED Requirements

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
