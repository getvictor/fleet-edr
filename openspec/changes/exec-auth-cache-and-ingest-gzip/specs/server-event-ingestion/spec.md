# Server Event Ingestion Specification

## MODIFIED Requirements

### Requirement: Authenticated batch event submission

The system SHALL expose `POST /api/events` that accepts a JSON array of event envelopes from an enrolled agent. The caller MUST present a per-host bearer token in the `Authorization` header; the system MUST reject requests whose token does not resolve to an enrolled host. When the request carries `Content-Encoding: gzip` the system SHALL decompress the body before parsing; a request without that header is read as-is, so an uncompressed caller stays supported and no agent/server version lockstep is required.

#### Scenario: A valid agent posts a batch

- **GIVEN** an enrolled host with a valid bearer token
- **WHEN** the agent submits a JSON array of well-formed event envelopes to `POST /api/events`
- **THEN** the system responds with HTTP 200 and a JSON body reporting the number of events accepted
- **AND** every submitted event is persisted before the response is returned

#### Scenario: A request without a host token is rejected

- **GIVEN** a client that omits or supplies an unrecognized bearer token
- **WHEN** the client submits any payload to `POST /api/events`
- **THEN** the system responds with HTTP 401 and does not persist any of the events

#### Scenario: A gzip-encoded batch is accepted and persisted

- **GIVEN** an enrolled host with a valid bearer token
- **WHEN** the agent submits a well-formed batch gzip-compressed with `Content-Encoding: gzip`
- **THEN** the system decompresses the body, responds with HTTP 200, and persists every event identically to the uncompressed path

### Requirement: Body size limit

The system SHALL cap the bytes it reads from the request body of `POST /api/events` at 10 MB. Bodies that exceed the cap MUST result in HTTP 413 with a typed `body_too_large` diagnostic, and no events from that batch are persisted. The 413 status (RFC 9110 §15.5.14) is the canonical "your body exceeded the limit" signal and matches the shape Elastic Fleet, Datadog, Splunk HEC, and CrowdStrike's ingestion endpoints all use; an agent that sees 413 SHOULD split larger telemetry into multiple batches under the cap rather than retry the same body.

The system MUST enforce the cap before allocating a buffer for the body so a malicious or misconfigured caller cannot trigger an arbitrary-size allocation. When the request advertises `Content-Length` greater than 10 MB the system MUST respond with 413 without reading any of the body; when the request uses chunked transfer-encoding the system MUST enforce the cap via a streaming reader and respond with 413 as soon as the cap is crossed.

When the request is `Content-Encoding: gzip`, the 10 MB cap SHALL apply to the DECOMPRESSED bytes: the system MUST bound the compressed input AND the decompressed output independently, so a small compressed body that expands past 10 MB (a decompression bomb) is rejected with HTTP 413 `body_too_large` rather than allocated in full. A request whose body is not a valid gzip stream (bad header, truncated, or corrupt) MUST be rejected with HTTP 400 and a typed `invalid_gzip` diagnostic, distinct from the 413 oversize signal, so the size-versus-malformed split stays honest.

#### Scenario: An oversized request body is rejected

- **GIVEN** an authenticated agent
- **WHEN** the request body exceeds 10 MB
- **THEN** the system responds with HTTP 413 and the body is `{"error":"body_too_large"}`
- **AND** no events from that batch are persisted

#### Scenario: A right-at-cap body is accepted

- **GIVEN** an authenticated agent submitting a JSON array whose serialized length is at or below 10 MB
- **WHEN** the batch is otherwise well-formed
- **THEN** the system reads the entire body, validates and persists every event, and returns HTTP 200

#### Scenario: A gzip decompression bomb is rejected

- **GIVEN** an authenticated agent sending `Content-Encoding: gzip`
- **WHEN** the compressed body is itself under the cap but decompresses to more than 10 MB
- **THEN** the system responds with HTTP 413 `body_too_large` without allocating the full decompressed payload
- **AND** no events from that batch are persisted

#### Scenario: A malformed gzip body is rejected

- **GIVEN** an authenticated agent sending `Content-Encoding: gzip`
- **WHEN** the request body is not a valid gzip stream
- **THEN** the system responds with HTTP 400 and a typed `invalid_gzip` diagnostic
- **AND** no events from that body are persisted
