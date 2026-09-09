# Server REST API Specification

## MODIFIED Requirements

### Requirement: Filterable alerts list

The system SHALL expose `GET /api/alerts` returning a JSON array of detection alerts. The response SHALL be filterable by host identifier, status, severity, source, and linked process identifier.

The `source` filter selects alerts by which subsystem raised them, so an operator can separate application-control blocks from catalog-rule detections without reading every row. Filters combine conjunctively: an alert must satisfy every filter supplied.

#### Scenario: An operator filters alerts by host

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/alerts?host_id=H`
- **THEN** the system responds with HTTP 200 and a JSON array
- **AND** every entry's host identifier equals `H`

#### Scenario: An operator combines status and severity filters

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/alerts?status=open&severity=critical`
- **THEN** the response includes only alerts whose status is `open` and whose severity is `critical`

#### Scenario: An operator filters alerts by source

- **GIVEN** a deployment with alerts from more than one source
- **WHEN** the client calls `GET /api/alerts?source=application_control`
- **THEN** the response includes only alerts whose source is `application_control`
- **AND** alerts raised by catalog detection rules are excluded
