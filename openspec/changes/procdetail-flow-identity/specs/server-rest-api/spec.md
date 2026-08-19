# server-rest-api delta: process-detail flows are attributed by generation identity

## MODIFIED Requirements

### Requirement: Per-process detail with re-exec chain

The system SHALL expose `GET /api/hosts/{host_id}/processes/{pid}` returning a single process record together with its network connections, DNS queries, and the ordered re-exec chain of prior generations on the same PID.

The endpoint SHALL accept an optional `pidversion` query parameter naming one generation of that PID. When it is supplied the system MUST return that exact generation, resolved by `(host, pid, pidversion)` identity, and MUST respond 404 when no generation of the PID carries it, rather than falling back to a different generation. When it is absent the system MUST resolve the generation from the `at` instant as before. Naming the generation is the only way to address any but the newest member of a re-exec chain, because a re-exec preserves the chain's original fork time so all its generations share one, and the as-of resolution can therefore only ever reach the most recently recorded one. A malformed `pidversion` MUST be rejected with HTTP 400 rather than ignored, so a bad value cannot silently return a different generation than the caller asked for.

The network connections and DNS queries returned SHALL be those belonging to the SPECIFIC process generation the response describes, not to every generation that shared the PID. A flow whose payload carries a `pidversion` SHALL be attributed by `(pid, pidversion)` identity alone, and the system MUST NOT additionally require its ingest time to fall inside the generation's lifetime window: a flow and its process's exit reach the server in separate uploads, so a short-lived process's flow routinely ingests after its own exit, and requiring the window drops exactly the flows an alert most often fired on. A flow whose payload carries no `pidversion` SHALL be attributed by an ingest-time window derived from the generation's lifetime, because identity is unavailable for it; that window MUST tolerate a flow arriving a full upload cycle after the exit rather than only a reordering within one upload. A flow carrying a `pidversion` that matches no generation of that PID MUST NOT be attributed to any generation by timing proximity.

#### Scenario: An operator inspects a process detail

- **GIVEN** a logged-in operator and a host plus PID with recorded activity
- **WHEN** the client calls `GET /api/hosts/{host_id}/processes/{pid}`
- **THEN** the system responds with HTTP 200 and a JSON object containing the process record, its network connections, and its DNS queries
- **AND** when the process has prior generations on the same PID the response carries those generations in oldest-first order as the re-exec chain

#### Scenario: The PID is not known on the host

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/hosts/{host_id}/processes/{pid}` for a PID that has no record on that host
- **THEN** the system responds with HTTP 404 and an error body

#### Scenario: A flow that ingests after its process exited is still attributed to it

- **GIVEN** a process generation that has exited, and a flow carrying that generation's `pidversion` whose ingest time is several seconds after the generation's exit ingest time
- **WHEN** the client requests that generation's detail
- **THEN** the response carries that flow among its network connections
- **AND** the attribution does not depend on the flow's ingest time falling inside the generation's lifetime window

#### Scenario: A sibling generation of the same PID does not claim the flow

- **GIVEN** two generations of one PID with different `pidversion`s, one of which owns a flow by identity, and a sibling that has not exited
- **WHEN** the client requests the sibling generation's detail
- **THEN** the response does not carry the other generation's flow
- **AND** requesting the owning generation's detail does carry it

#### Scenario: A named generation of a re-exec chain is addressable

- **GIVEN** a PID with two generations from a re-exec, which therefore share one fork time, the older of which owns a flow by identity
- **WHEN** the client requests that PID's detail supplying the older generation's `pidversion`
- **THEN** the response describes the older generation and carries its flow
- **AND** requesting the same PID and instant WITHOUT a `pidversion` describes the newest generation instead, which is the only generation the as-of resolution can reach

#### Scenario: A pidversion naming no generation is not silently substituted

- **GIVEN** a PID with recorded generations on a host
- **WHEN** the client requests that PID's detail supplying a `pidversion` that no generation of it carries
- **THEN** the system responds with HTTP 404 rather than describing a different generation
- **AND** a `pidversion` that is not a parseable unsigned 32-bit value is rejected with HTTP 400

#### Scenario: A flow without a kernel generation is attributed by the lifetime window

- **GIVEN** a flow whose payload carries no `pidversion`, recorded against a PID whose generation has a known lifetime
- **WHEN** the client requests that generation's detail
- **THEN** the response carries that flow when its ingest time falls inside the generation's window
- **AND** a flow carrying `pidversion` 0 is treated as carrying a real kernel generation rather than as carrying none
