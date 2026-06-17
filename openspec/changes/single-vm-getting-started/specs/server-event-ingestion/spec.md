# Server event ingestion: content-neutral acceptance delta

## ADDED Requirements

### Requirement: Ingest acceptance is content-neutral

The authenticated event-ingest path SHALL decide acceptance solely on host-token authentication, structural request validation (JSON shape, per-request event count, body size, and host-id match), and server health. It SHALL NOT inspect event payload content for attack signatures, and SHALL NOT reject a batch because its captured command lines, file paths, or network indicators resemble an attack. Agent telemetry legitimately carries such strings, so content inspection belongs to no layer of a supported deployment. Concretely, the path returns `200` on success, `401` for a missing or invalid host token, `400` or `413` for a malformed or oversized batch, and `500`/`503` on a server or database error; it SHALL never return a `403` content-block. A `403` reaching an agent is therefore diagnosably produced by an edge in front of the server, not by the server.

#### Scenario: A batch whose contents resemble an attack is accepted

- **GIVEN** an enrolled host whose host token pins its `host_id`
- **WHEN** it submits a well-formed event batch whose payload fields contain attack signatures (a reverse-shell command line, a C2 URL, and a SQL-injection fragment)
- **THEN** the server accepts the batch with `200` and persists its events, identically to a benign batch of the same shape

#### Scenario: The ingest path never returns a content-block status

- **GIVEN** any request to the authenticated ingest path, across its success and validation-failure outcomes
- **WHEN** the server handles it
- **THEN** the response status is `200` (success), `401` (authentication), `400` or `413` (validation), or `500`/`503` (server), and never `403`
