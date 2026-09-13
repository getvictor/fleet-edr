## MODIFIED Requirements

### Requirement: Filterable alerts list

The system SHALL expose `GET /api/alerts` returning a JSON array of detection alerts. The response SHALL be filterable by host identifier, status, severity, source, rule identifier, linked process identifier, and disposition.

The `source` filter selects alerts by which subsystem raised them, so an operator can separate application-control blocks from catalog-rule detections without reading every row. Filters combine conjunctively: an alert must satisfy every filter supplied.

The `disposition` filter selects between alerts and monitor records. It SHALL default to `alert`, so a caller that does not ask for monitor records never receives one and no existing client changes behaviour. `disposition=monitor` SHALL return monitor records only, and any other value SHALL be rejected with HTTP 400. Each entry SHALL report its disposition.

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

#### Scenario: The list excludes monitor records unless they are asked for

- **GIVEN** a deployment with alerts and monitor records
- **WHEN** the client calls `GET /api/alerts` with no disposition
- **THEN** every entry has disposition `alert`
- **AND** `GET /api/alerts?disposition=monitor&rule_id=R` returns only monitor records of rule `R`

#### Scenario: An unknown disposition is rejected

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/alerts?disposition=everything`
- **THEN** the system responds with HTTP 400 and an error body

### Requirement: Alert detail with linked event ids

The system SHALL expose `GET /api/alerts/{id}` returning a single alert or monitor record. The response SHALL include its host identifier, rule identifier, disposition, severity, title, description, linked process identifier, MITRE ATT&CK technique identifiers, status, and the list of event identifiers that triggered it. A monitor record is served here like an alert so an operator can open it and pivot from it, and the disposition is what tells a client not to offer triage on it.

The change from the prior requirement is that the endpoint also serves monitor records and reports the disposition.

#### Scenario: An operator opens an alert

- **GIVEN** a logged-in operator and an existing alert
- **WHEN** the client calls `GET /api/alerts/{id}`
- **THEN** the system responds with HTTP 200 and a JSON object
- **AND** the object includes the rule identifier, severity, title, description, linked process identifier, technique identifiers, status, and the list of triggering event identifiers

#### Scenario: The alert id is unknown

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/alerts/{id}` with an identifier that does not exist
- **THEN** the system responds with HTTP 404 and an error body

#### Scenario: The detail of a monitor record reports its disposition

- **GIVEN** a logged-in operator and an existing monitor record
- **WHEN** the client calls `GET /api/alerts/{id}` for it
- **THEN** the system responds with HTTP 200, and the object reports disposition `monitor` along with its triggering event identifiers

### Requirement: Update alert lifecycle status

The system SHALL expose `PUT /api/alerts/{id}` accepting a JSON body that sets the alert status to one of `open`, `acknowledged`, or `resolved`. Any other status value MUST be rejected. On success the system MUST record which authenticated user performed the change. A monitor record SHALL NOT be triaged, so a status change addressed to one MUST be rejected and the record left unchanged.

#### Scenario: An operator resolves an alert

- **GIVEN** a logged-in operator and an existing alert
- **WHEN** the client issues `PUT /api/alerts/{id}` with body `{"status": "resolved"}`
- **THEN** the system responds with HTTP 204
- **AND** the alert's stored status becomes `resolved`
- **AND** the identity of the operator that performed the change is recorded

#### Scenario: An invalid status value is supplied

- **GIVEN** a logged-in operator
- **WHEN** the client issues `PUT /api/alerts/{id}` with a status that is not one of `open`, `acknowledged`, or `resolved`
- **THEN** the system responds with HTTP 400 and the alert is not modified

#### Scenario: A status change addressed to a monitor record is rejected

- **GIVEN** a logged-in operator and an existing monitor record
- **WHEN** the client issues `PUT /api/alerts/{id}` for it with body `{"status": "acknowledged"}`
- **THEN** the system responds with HTTP 400 and the monitor record is not modified
