# Server REST API Specification (delta)

## MODIFIED Requirements

### Requirement: List enrolled hosts

The system SHALL expose `GET /api/hosts` returning a JSON array of enrolled hosts. Each entry SHALL include the host identifier, the count of events seen for that host, the most recent timestamp at which any event from the host was observed, and the host's enrollment hostname and operating-system version. The hostname and OS version SHALL be sourced from the host's enrollment record; a host that has sent events but has no enrollment record SHALL still appear in the array with an empty hostname and an empty OS version rather than being omitted.

The change from the prior requirement is the addition of the enrollment hostname and OS version to each entry, sourced by joining the enrollment record on the shared host identifier, with empty values (not omission) for an un-enrolled host.

#### Scenario: An operator opens the hosts dashboard

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/hosts`
- **THEN** the system responds with HTTP 200 and a JSON array
- **AND** every entry contains the host identifier, an event count, and a last-seen timestamp

#### Scenario: Host list rows carry enrollment hostname and OS version

- **GIVEN** one host with an enrollment record (hostname and OS version) and one host that has sent events but has no enrollment record
- **WHEN** the client calls `GET /api/hosts`
- **THEN** the enrolled host's entry carries its enrollment hostname and OS version
- **AND** the un-enrolled host still appears with an empty hostname and an empty OS version
