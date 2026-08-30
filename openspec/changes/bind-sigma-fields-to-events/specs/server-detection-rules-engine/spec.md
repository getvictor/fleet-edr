# Server detection rules engine: bind Sigma field names to our event payloads delta

## ADDED Requirements

### Requirement: Our events supply the Sigma fields a rule reads

The system SHALL map Sigma's field names onto our event payloads, so a rule written in the Sigma format can be evaluated against captured telemetry.

The system SHALL resolve a rule's logsource category to the event type whose payload supplies its fields, and SHALL decline a category for which it supplies no fields rather than accepting one it could name but not populate.

The system SHALL decode an event's payload once and reuse it for every rule evaluated against that event. Field access itself SHALL allocate nothing, because it runs for every field of every rule against every event.

The system SHALL report a field as absent when the payload does not carry it, so that a rule matching on absence behaves as its author intended.

The system SHALL supply a file-event rule's target filename only for an open that carries write intent. The Sigma category names file creation and modification rather than any access, and read-only opens of a watched path are routine background activity, so supplying them would present known noise to every such rule as a detection.

#### Scenario: Our events supply the Sigma fields a rule reads

- **GIVEN** a rule whose fields are all mapped for its event type
- **WHEN** an event of that type is evaluated
- **THEN** the rule sees the values its payload carries

#### Scenario: A read-only open supplies no target filename

- **GIVEN** a file-open event that opens a path for reading only
- **WHEN** a file-event rule is evaluated against it
- **THEN** the rule sees no target filename, and does not match

#### Scenario: A rule is inert against an event type it does not name

- **GIVEN** a rule whose logsource names one event type
- **WHEN** it is evaluated against an event of a different type
- **THEN** it does not match, rather than matching on a field that happens to share a name

### Requirement: A rule reading a field we do not supply is refused when it loads

The system SHALL refuse to load a rule that reads a field its event type does not supply, naming both the unsupplied fields and the fields that are available.

A rule naming a field we never populate would evaluate to false on that field for every event, for as long as it remained installed. That is indistinguishable from the adversary behaviour never occurring, so it is reported when the rule loads rather than discovered from an absence of alerts.

The system SHALL refuse a rule whose event type has no field mapping at all, distinctly from one whose fields are individually unavailable, so the reader can tell "we do not map this kind of event" from "we do not have this field".

#### Scenario: A rule reading a field we do not supply is refused

- **GIVEN** a rule reading a field its event type does not supply
- **WHEN** the rule is loaded
- **THEN** loading fails, naming the field and the fields that are available
