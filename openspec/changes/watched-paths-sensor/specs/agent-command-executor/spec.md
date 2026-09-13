## ADDED Requirements

### Requirement: Set-watched-paths command

The system SHALL execute a `set_watched_paths` command by forwarding the watched-path set to the local Endpoint Security extension, and SHALL report the set's `version` and the number of entries forwarded.

The payload SHALL carry `{version, paths}` and MAY carry `epoch`, where each `paths` entry carries `{path, match}`. The executor SHALL validate, before forwarding, that `version` is a positive integer and that `paths` is a JSON array, and SHALL NOT validate the entries or `epoch`: they are addressed to the extension, which skips an entry it does not understand, and the agent forwards the raw payload bytes so the wire shape stays identical across server, agent, and extension. An empty `paths` array SHALL be forwarded, since it is how the server removes every path it added.

#### Scenario: Watched paths forwarded successfully

- **GIVEN** a `set_watched_paths` command with a positive `version`, a `paths` array, and a configured extension bridge
- **WHEN** the agent forwards the payload to the extension
- **THEN** the extension receives exactly the payload bytes the server sent
- **AND** the executor reports completed with the version and the count of entries in the payload

#### Scenario: A watched-path payload is invalid

- **GIVEN** a `set_watched_paths` command whose payload is not JSON, whose `version` is absent, zero, or negative, or whose `paths` is absent or not a JSON array
- **WHEN** the executor decodes the payload
- **THEN** the executor reports failed with a reason identifying the invalid field
- **AND** the extension bridge is not invoked

#### Scenario: The watched-path set cannot reach the extension

- **GIVEN** a valid `set_watched_paths` payload
- **WHEN** the agent has no extension bridge, or the transport to the extension returns an error
- **THEN** the executor reports failed with a reason that says which of the two happened
