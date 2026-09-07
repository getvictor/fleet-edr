# server-rest-api delta

## MODIFIED Requirements

### Requirement: Per-host process forest

The system SHALL expose `GET /api/hosts/{host_id}/tree` returning the process forest for that host. The response SHALL nest each process under its parent and SHALL attach the network connections and DNS queries that occurred during each process's lifetime. By default the response SHALL collapse repeated identical-path leaf siblings under the same parent into aggregated nodes, each carrying the group's count, its exited-versus-running split, its first and last fork times, and a capped sample of the underlying members, nested in the forest exactly where the collapsed siblings sat. The endpoint SHALL accept an optional `flatten` boolean query parameter; when set it returns the raw, un-aggregated forest with every node. The endpoint SHALL also accept an optional `pin` query parameter naming a single process by its id; that process SHALL be kept a first-class node, never folded into a sibling aggregate, so a client such as the alert view can always locate the alerted process by its real id even when it has identical siblings.

The response SHALL additionally carry result metadata describing what the read did NOT return: `total_matched`, the count of every process row whose lifetime overlaps the requested window, computed independent of the row limit; `returned`, the count of rows the limit admitted, before any aggregation folded them; and `truncated`, whether the limit dropped rows. `total_matched` SHALL be counted with the same window predicate that selects the rows, so the two can never disagree. `total_matched` SHALL always be a real count for this endpoint; the tree read is scoped to a single host and window and MUST NOT return a not-counted sentinel. A client MUST be able to report what is missing using only these fields, without re-deriving the server's effective limit.

#### Scenario: An operator views a host's process tree

- **GIVEN** a logged-in operator and a known host with recorded activity
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree`
- **THEN** the system responds with HTTP 200 and a JSON object containing the forest of root processes
- **AND** each process node carries its child processes and the network connections and DNS queries linked to it

#### Scenario: A time range is supplied

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree` with optional `from` or `to` nanosecond bounds
- **THEN** the response is restricted to processes whose lifetime overlaps the specified window

#### Scenario: Repeated identical siblings collapse into an aggregated node

- **GIVEN** a logged-in operator and a host where a parent spawned many childless children of the same image path and binary identity
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree` without `flatten`
- **THEN** those siblings appear as a single aggregated node carrying the group count, the exited-versus-running split, the first and last fork times, and a capped sample of the members

#### Scenario: An operator opts out of aggregation with flatten

- **GIVEN** a logged-in operator viewing a host whose tree contains aggregated groups
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree` with the `flatten` parameter set
- **THEN** the response contains the raw forest with every sibling as its own node and no aggregated nodes

#### Scenario: A pinned process is never folded into an aggregate

- **GIVEN** a logged-in operator and a host where the pinned process has one or more identical-image sibling leaves that would otherwise collapse into an aggregated node
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree` with `pin` set to that process's id
- **THEN** the pinned process appears as its own first-class node carrying its real id, not folded into any aggregated node

#### Scenario: A window matching more processes than the limit is reported as truncated

- **GIVEN** a logged-in operator and a host whose window overlaps more process rows than the effective row limit
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree`
- **THEN** the response sets `truncated` to true
- **AND** `total_matched` equals the true count of overlapping rows, not the limit
- **AND** `returned` equals the number of rows the limit admitted

#### Scenario: A window inside the limit is not reported as truncated

- **GIVEN** a logged-in operator and a host whose window overlaps fewer process rows than the effective row limit
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree`
- **THEN** the response sets `truncated` to false
- **AND** `returned` equals `total_matched`

#### Scenario: The reported total ignores the requested limit

- **GIVEN** a logged-in operator and a host whose window overlaps a fixed number of process rows
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree` twice with different `limit` values
- **THEN** both responses report the same `total_matched`
