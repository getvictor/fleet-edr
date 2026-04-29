# Server REST API Specification

## Purpose

The server REST API is the read and triage surface that the admin web UI and any first-party automation use to inspect the
EDR's state. It exposes the materialized host inventory, the per-host process forest, the per-process detail (including
network connections, DNS queries, and same-PID re-exec chains), and the persisted alerts produced by the detection engine.
It also lets an operator update the lifecycle status of an alert.

The capability is the contract between the backend and any browser client: every field a client renders comes from these
endpoints, and the JSON shapes here are stable across non-breaking releases. Endpoints described in this capability are the
session-authenticated UI surface; agent-facing endpoints (event ingestion, command polling) live in their own capabilities.

## Requirements

### Requirement: Session authentication and CSRF protection

The system SHALL require a valid session cookie on every endpoint defined in this capability. For unsafe methods (`POST`,
`PUT`, `DELETE`) the system MUST additionally require a matching CSRF token header. Requests that fail either check MUST be
rejected before any business logic executes.

#### Scenario: A browser without a session cookie calls a UI endpoint

- **GIVEN** a client that does not present a valid `edr_session` cookie
- **WHEN** the client calls any endpoint defined in this capability
- **THEN** the system responds with HTTP 401 and an error body
- **AND** no host, process, or alert data is returned

#### Scenario: A state-changing call omits the CSRF token

- **GIVEN** a client with a valid session cookie
- **WHEN** the client issues `PUT /api/v1/alerts/{id}` without a matching `X-CSRF-Token` header
- **THEN** the system responds with HTTP 403 and the alert is not modified

### Requirement: List enrolled hosts

The system SHALL expose `GET /api/v1/hosts` returning a JSON array of enrolled hosts. Each entry SHALL include the host
identifier, the count of events seen for that host, and the most recent timestamp at which any event from the host was
observed.

#### Scenario: An operator opens the hosts dashboard

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/v1/hosts`
- **THEN** the system responds with HTTP 200 and a JSON array
- **AND** every entry contains the host identifier, an event count, and a last-seen timestamp

### Requirement: Per-host process forest

The system SHALL expose `GET /api/v1/hosts/{host_id}/tree` returning the process forest for that host. The response SHALL
nest each process under its parent and SHALL attach the network connections and DNS queries that occurred during each
process's lifetime.

#### Scenario: An operator views a host's process tree

- **GIVEN** a logged-in operator and a known host with recorded activity
- **WHEN** the client calls `GET /api/v1/hosts/{host_id}/tree`
- **THEN** the system responds with HTTP 200 and a JSON object containing the forest of root processes
- **AND** each process node carries its child processes and the network connections and DNS queries linked to it

#### Scenario: A time range is supplied

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/v1/hosts/{host_id}/tree` with optional `from` or `to` nanosecond bounds
- **THEN** the response is restricted to processes whose lifetime overlaps the specified window

### Requirement: Per-process detail with re-exec chain

The system SHALL expose `GET /api/v1/hosts/{host_id}/processes/{pid}` returning a single process record together with its
network connections, DNS queries, and the ordered re-exec chain of prior generations on the same PID.

#### Scenario: An operator inspects a process detail

- **GIVEN** a logged-in operator and a host plus PID with recorded activity
- **WHEN** the client calls `GET /api/v1/hosts/{host_id}/processes/{pid}`
- **THEN** the system responds with HTTP 200 and a JSON object containing the process record, its network connections, and
  its DNS queries
- **AND** when the process has prior generations on the same PID the response carries those generations in oldest-first
  order as the re-exec chain

#### Scenario: The PID is not known on the host

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/v1/hosts/{host_id}/processes/{pid}` for a PID that has no record on that host
- **THEN** the system responds with HTTP 404 and an error body

### Requirement: Filterable alerts list

The system SHALL expose `GET /api/v1/alerts` returning a JSON array of detection alerts. The response SHALL be filterable
by host identifier, status, severity, and linked process identifier.

#### Scenario: An operator filters alerts by host

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/v1/alerts?host_id=H`
- **THEN** the system responds with HTTP 200 and a JSON array
- **AND** every entry's host identifier equals `H`

#### Scenario: An operator combines status and severity filters

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/v1/alerts?status=open&severity=critical`
- **THEN** the response includes only alerts whose status is `open` and whose severity is `critical`

### Requirement: Alert detail with linked event ids

The system SHALL expose `GET /api/v1/alerts/{id}` returning a single alert. The response SHALL include the alert's host
identifier, rule identifier, severity, title, description, linked process identifier, MITRE ATT&CK technique identifiers,
status, and the list of event identifiers that triggered the alert.

#### Scenario: An operator opens an alert

- **GIVEN** a logged-in operator and an existing alert
- **WHEN** the client calls `GET /api/v1/alerts/{id}`
- **THEN** the system responds with HTTP 200 and a JSON object
- **AND** the object includes the rule identifier, severity, title, description, linked process identifier, technique
  identifiers, status, and the list of triggering event identifiers

#### Scenario: The alert id is unknown

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/v1/alerts/{id}` with an identifier that does not exist
- **THEN** the system responds with HTTP 404 and an error body

### Requirement: Update alert lifecycle status

The system SHALL expose `PUT /api/v1/alerts/{id}` accepting a JSON body that sets the alert status to one of `open`,
`acknowledged`, or `resolved`. Any other status value MUST be rejected. On success the system MUST record which
authenticated user performed the change.

#### Scenario: An operator resolves an alert

- **GIVEN** a logged-in operator and an existing alert
- **WHEN** the client issues `PUT /api/v1/alerts/{id}` with body `{"status": "resolved"}`
- **THEN** the system responds with HTTP 204
- **AND** the alert's stored status becomes `resolved`
- **AND** the identity of the operator that performed the change is recorded

#### Scenario: An invalid status value is supplied

- **GIVEN** a logged-in operator
- **WHEN** the client issues `PUT /api/v1/alerts/{id}` with a status that is not one of `open`, `acknowledged`, or
  `resolved`
- **THEN** the system responds with HTTP 400 and the alert is not modified

### Requirement: JSON response format and error shape

The system SHALL return successful response bodies as `application/json` with a UTF-8 encoding. Error responses SHALL be
returned as JSON with a single `error` field whose value is a stable typed error code (for example `{"error":
"unauthorized"}`) so clients can branch on the code without parsing free-form prose. The same `ErrorResponse` shape MUST
be used for every 4xx and 5xx response defined in this capability.

#### Scenario: An endpoint returns an error

- **GIVEN** a logged-in operator
- **WHEN** any endpoint defined in this capability fails with a 4xx or 5xx status
- **THEN** the response body is a JSON object with an `error` field carrying a stable typed error code
- **AND** clients can dispatch on the code without further parsing

#### Scenario: A successful response is JSON

- **GIVEN** any successful call to an endpoint defined in this capability
- **WHEN** the response body is non-empty
- **THEN** the `Content-Type` is `application/json` and the body parses as valid JSON

