# server-rest-api

## MODIFIED Requirements

### Requirement: Per-host process forest

The system SHALL expose `GET /api/hosts/{host_id}/tree` returning the process forest for that host. The response SHALL nest each process under its parent and SHALL attach the network connections and DNS queries that occurred during each process's lifetime. By default the response SHALL collapse repeated identical-path leaf siblings under the same parent into aggregated nodes, each carrying the group's count, its exited-versus-running split, its first and last fork times, and a capped sample of the underlying members, nested in the forest exactly where the collapsed siblings sat. The endpoint SHALL accept an optional `flatten` boolean query parameter; when set it returns the raw, un-aggregated forest with every node. The endpoint SHALL also accept an optional `pin` query parameter naming a single process by its id; that process SHALL be kept a first-class node, never folded into a sibling aggregate, so a client such as the alert view can always locate the alerted process by its real id even when it has identical siblings.

The response SHALL additionally carry result metadata describing what the read did NOT return: `total_matched`, the count of process rows whose lifetime overlaps the requested window; `returned`, the count of rows the limit admitted, before any aggregation folded them; `total_matched_capped`, whether that count is a floor rather than a total; and `truncated`, whether the limit dropped rows. `total_matched` SHALL be counted with the same window predicate that selects the rows, so the two can never disagree. A client MUST be able to report what is missing using only these fields, without re-deriving the server's effective limit.

`truncated` SHALL be established by the read itself, by fetching one row beyond the requested limit, and SHALL NOT be derived from `total_matched`. The count behind that number is bounded and may give up, so deriving truncation from it reports a partial forest as complete on exactly the hosts where the count cannot finish, which is where a partial forest is most likely. A read proven untruncated SHALL skip the count entirely, since it holds every row that matched, and SHALL NOT set `total_matched_capped`.

Counting SHALL be bounded both by a row bound and by a time budget, and `total_matched` is therefore exact when the count completed within both and a floor otherwise, with `total_matched_capped` saying which. A count that exhausts its time budget SHALL NOT fail the request: the rows are already in hand and the request is answerable without the number, so the rows returned become the floor and the response reports "more than what you can see". The row bound caps rows emitted rather than rows examined, so a window matching fewer rows than the bound still walks its whole range to prove it; the time budget is the backstop for that, and it is why a bound alone is not sufficient. An unbounded count is what this replaces, and it took the endpoint down: on a dogfood host carrying 5.4 million process rows, a 24-hour window matched 542,268 of them and the count ran past 120 seconds against a 30-second server write timeout, so the request returned 500 and the operator saw a failed graph. The row read itself was never slow, at about 0.1 seconds for the same window, because its `ORDER BY fork_time_ns DESC LIMIT` lets the scan stop early. Counting SHALL use that same access path so its cost is bounded by the bound rather than by how much the window matched.

The exactness given up buys a request that always answers. A denominator past the bound tells an operator nothing they act on differently: the decision a truncated tree drives is to narrow the window, and "more than 10,000" drives it as well as "542,268" does. A number that sometimes takes two minutes and then fails is worth less than a bounded one that always arrives.

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
- **AND** `total_matched` equals the true count of overlapping rows when that count is below the counting bound, not the limit
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

#### Scenario: Counting stops at its bound rather than scanning the whole window

- **GIVEN** a host whose window overlaps far more process rows than the counting bound
- **WHEN** the client calls `GET /api/hosts/{host_id}/tree`
- **THEN** `total_matched` equals the counting bound rather than the true number of overlapping rows
- **AND** `total_matched_capped` is true
- **AND** the response is returned rather than failing on a server timeout
- **AND** a window matching exactly the counting bound reports that number with `total_matched_capped` false, because nothing lies beyond it
- **AND** a count that exhausts its time budget reports the rows returned as the floor, with `total_matched_capped` true and `truncated` still true
