# Server REST API Specification

## Purpose

The server REST API is the read and triage surface that the admin web UI and any first-party automation use to inspect the EDR's state. It exposes the materialized host inventory, the per-host process forest, the per-process detail (including network connections, DNS queries, and same-PID re-exec chains), and the persisted alerts produced by the detection engine. It also lets an operator update the lifecycle status of an alert.

The capability is the contract between the backend and any browser client: every field a client renders comes from these endpoints, and the JSON shapes here are stable across non-breaking releases. Endpoints described in this capability are the session-authenticated UI surface; agent-facing endpoints (event ingestion, command polling) live in their own capabilities.

## Requirements

### Requirement: Session authentication and CSRF protection

The system SHALL require a valid session cookie on every endpoint defined in this capability. For unsafe methods (`POST`, `PUT`, `DELETE`) the system MUST additionally require a matching CSRF token header. Requests that fail either check MUST be rejected before any business logic executes.

#### Scenario: A browser without a session cookie calls a UI endpoint

- **GIVEN** a client that does not present a valid `edr_session` cookie
- **WHEN** the client calls any endpoint defined in this capability
- **THEN** the system responds with HTTP 401 and an error body
- **AND** no host, process, or alert data is returned

#### Scenario: A state-changing call omits the CSRF token

- **GIVEN** a client with a valid session cookie
- **WHEN** the client issues `PUT /api/alerts/{id}` without a matching `X-CSRF-Token` header
- **THEN** the system responds with HTTP 403 and the alert is not modified

### Requirement: List enrolled hosts

The system SHALL expose `GET /api/hosts` returning a JSON array of enrolled hosts. Each entry SHALL include the host identifier, the count of events seen for that host, the most recent timestamp at which any event from the host was observed, and the host's enrollment hostname, operating-system version, and platform. The hostname, OS version, and platform SHALL be sourced from the host's enrollment record; a host that has sent events but has no enrollment record SHALL still appear in the array with an empty hostname, an empty OS version, and an empty platform rather than being omitted.

The change from the prior requirement is the addition of the host platform to each entry, sourced by the same join on the shared host identifier as the hostname and OS version, with an empty value (not omission) for an un-enrolled host.

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

#### Scenario: Host list rows carry the host platform

- **GIVEN** one host with an enrollment record naming its platform and one host that has sent events but has no enrollment record
- **WHEN** the client calls `GET /api/hosts`
- **THEN** the enrolled host's entry carries its enrollment platform
- **AND** the un-enrolled host still appears with an empty platform

### Requirement: Per-host process forest

The system SHALL expose `GET /api/hosts/{host_id}/tree` returning the process forest for that host. The response SHALL nest each process under its parent and SHALL attach the network connections and DNS queries that occurred during each process's lifetime. By default the response SHALL collapse repeated identical-path leaf siblings under the same parent into aggregated nodes, each carrying the group's count, its exited-versus-running split, its first and last fork times, and a capped sample of the underlying members, nested in the forest exactly where the collapsed siblings sat. The endpoint SHALL accept an optional `flatten` boolean query parameter; when set it returns the raw, un-aggregated forest with every node. The endpoint SHALL also accept an optional `pin` query parameter naming a single process by its id; that process SHALL be kept a first-class node, never folded into a sibling aggregate, so a client such as the alert view can always locate the alerted process by its real id even when it has identical siblings.

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

### Requirement: Per-process detail with re-exec chain

The system SHALL expose `GET /api/hosts/{host_id}/processes/{pid}` returning a single process record together with its network connections, DNS queries, and the ordered re-exec chain of prior generations on the same PID.

#### Scenario: An operator inspects a process detail

- **GIVEN** a logged-in operator and a host plus PID with recorded activity
- **WHEN** the client calls `GET /api/hosts/{host_id}/processes/{pid}`
- **THEN** the system responds with HTTP 200 and a JSON object containing the process record, its network connections, and its DNS queries
- **AND** when the process has prior generations on the same PID the response carries those generations in oldest-first order as the re-exec chain

#### Scenario: The PID is not known on the host

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/hosts/{host_id}/processes/{pid}` for a PID that has no record on that host
- **THEN** the system responds with HTTP 404 and an error body

### Requirement: Filterable alerts list

The system SHALL expose `GET /api/alerts` returning a JSON array of detection alerts. The response SHALL be filterable by host identifier, status, severity, and linked process identifier.

#### Scenario: An operator filters alerts by host

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/alerts?host_id=H`
- **THEN** the system responds with HTTP 200 and a JSON array
- **AND** every entry's host identifier equals `H`

#### Scenario: An operator combines status and severity filters

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/alerts?status=open&severity=critical`
- **THEN** the response includes only alerts whose status is `open` and whose severity is `critical`

### Requirement: Alert detail with linked event ids

The system SHALL expose `GET /api/alerts/{id}` returning a single alert. The response SHALL include the alert's host identifier, rule identifier, severity, title, description, linked process identifier, MITRE ATT&CK technique identifiers, status, and the list of event identifiers that triggered the alert.

#### Scenario: An operator opens an alert

- **GIVEN** a logged-in operator and an existing alert
- **WHEN** the client calls `GET /api/alerts/{id}`
- **THEN** the system responds with HTTP 200 and a JSON object
- **AND** the object includes the rule identifier, severity, title, description, linked process identifier, technique identifiers, status, and the list of triggering event identifiers

#### Scenario: The alert id is unknown

- **GIVEN** a logged-in operator
- **WHEN** the client calls `GET /api/alerts/{id}` with an identifier that does not exist
- **THEN** the system responds with HTTP 404 and an error body

### Requirement: Update alert lifecycle status

The system SHALL expose `PUT /api/alerts/{id}` accepting a JSON body that sets the alert status to one of `open`, `acknowledged`, or `resolved`. Any other status value MUST be rejected. On success the system MUST record which authenticated user performed the change.

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

### Requirement: JSON response format and error shape

The system SHALL return successful response bodies as `application/json` with a UTF-8 encoding. Error responses SHALL be returned as JSON with a single `error` field whose value is a stable typed error code (for example `{"error": "unauthorized"}`) so clients can branch on the code without parsing free-form prose. The same `ErrorResponse` shape MUST be used for every 4xx and 5xx response defined in this capability.

#### Scenario: An endpoint returns an error

- **GIVEN** a logged-in operator
- **WHEN** any endpoint defined in this capability fails with a 4xx or 5xx status
- **THEN** the response body is a JSON object with an `error` field carrying a stable typed error code
- **AND** clients can dispatch on the code without further parsing

#### Scenario: A successful response is JSON

- **GIVEN** any successful call to an endpoint defined in this capability
- **WHEN** the response body is non-empty
- **THEN** the `Content-Type` is `application/json` and the body parses as valid JSON

### Requirement: Registered authed routes are reachable through the composed router

Every authed API route a bounded context registers SHALL be reachable through the composed outer router with its session-authentication boundary applied. The set of session-protected routes SHALL be derived from what the contexts register rather than maintained as a separate hand-edited allowlist, so a registered authed route can never be omitted from the protected surface. An unauthenticated request to a registered authed route SHALL receive the session middleware's JSON authentication failure, never a fall-through to the single-page-app HTML catch-all.

#### Scenario: A registered authed route is session-protected, not SPA fall-through

- **GIVEN** a bounded context registers an authed API route
- **WHEN** an unauthenticated request hits that route through the composed router
- **THEN** the response is the session-authentication failure as JSON
- **AND** it is not the single-page-app HTML catch-all

### Requirement: Fleet-wide connection and DNS search endpoints

The system SHALL expose `GET /api/search/connections` and `GET /api/search/dns`, each authorized by the process-read action, returning events from the archive across all hosts: connections whose remote address equals a requested value, and DNS queries whose query name equals it. Each endpoint SHALL accept the artifact value (optional; when absent or empty the endpoint lists the most recent events of that type across the fleet rather than rejecting the request, mirroring the process search), an optional `host_id` scoping the search to one host, and a `from`/`to` window over ingest time. Results SHALL be ordered newest-first, paginated by an opaque keyset cursor over `(timestamp_ns, event_id)` such that paging the full set yields every matching event exactly once with no skips or duplicates, and each response SHALL carry the page of events, a `next_cursor` when more remain, and `total_matched`. For the recent-events listing (no artifact value) the endpoint MAY report `total_matched` as not computed (a negative sentinel) to avoid an expensive fleet-wide count; a filtered (artifact-valued) search SHALL report the exact `total_matched`. Pagination is driven by `next_cursor`, so it does not depend on the total. A malformed cursor SHALL be rejected with 400.

#### Scenario: Connection search finds a remote address across hosts

- **GIVEN** two hosts that each connected to the same remote address, plus connections to other addresses
- **WHEN** the client calls `GET /api/search/connections` with that address
- **THEN** the response contains the matching connection from each host and no others
- **AND** `total_matched` equals that count

#### Scenario: DNS search finds a query name across hosts

- **GIVEN** DNS queries for a domain on more than one host, plus queries for other domains
- **WHEN** the client calls `GET /api/search/dns` with that domain
- **THEN** the response contains only the matching queries, drawn from every host

#### Scenario: Host filter scopes the search

- **GIVEN** a fleet-wide artifact match set
- **WHEN** the client adds a `host_id`
- **THEN** the response contains only that host's matching events

#### Scenario: Absent artifact value lists recent events

- **GIVEN** a request with no artifact value
- **WHEN** the endpoint processes it
- **THEN** it returns the most recent events of that type across the fleet, newest-first, with no artifact filter applied
- **AND** it does not compute a fleet-wide total, reporting `total_matched` as the not-computed sentinel

#### Scenario: Keyset pagination is stable and complete

- **GIVEN** a matching set larger than one page
- **WHEN** the client pages through it following `next_cursor` until none is returned
- **THEN** the concatenation of pages is every matching event exactly once, newest-first, with no duplicate or skipped event

### Requirement: Fleet-wide process search endpoint

The system SHALL expose `GET /api/search/processes` returning processes matching a set of composable filters across all hosts, authorized by the process-read action. Supported filters, all optional and combined with AND in the database query (not in application code): `host_id` (exact; absent means every host), `path` (substring), `hash` (exact SHA-256), `uid` (exact), a `from`/`to` fork-time window, `exit_reason` (exact), and `signing` (a derived signer class: `unsigned`, `ad-hoc`, `platform`, `developer-id`, or `signed`). A `signing` or `exit_reason` value outside its accepted vocabulary SHALL be rejected with 400 rather than silently applied as a filter that matches nothing, so an analyst can trust that a typed filter was understood. Results SHALL be ordered newest-first by fork time with the row identifier breaking ties, and paginated by an opaque keyset cursor such that paging through the full result set yields every matching row exactly once with no skips or duplicates even as new processes are ingested concurrently. Each response SHALL carry the page of rows, a `next_cursor` when more rows remain (absent or empty on the last page), and `total_matched`, the count of all rows matching the filters independent of pagination. For the fully-unfiltered fleet browse (no filter set) the endpoint MAY report `total_matched` as not computed (a negative sentinel) to avoid an expensive count over the whole process table; any filter (even a lone `host_id` or time window, whose count is index-cheap) restores the exact count. Pagination is driven by `next_cursor`, so it does not depend on the total. A malformed cursor SHALL be rejected with 400.

#### Scenario: Filters compose across hosts

- **GIVEN** processes on several hosts, some unsigned, some with uid 0
- **WHEN** the client calls `GET /api/search/processes` with `signing=unsigned` and `uid=0`
- **THEN** the response contains exactly the processes that are both unsigned and uid 0, drawn from every host
- **AND** `total_matched` equals that count

#### Scenario: Unfiltered browse skips the total count

- **GIVEN** a fully-unfiltered request (no filter set)
- **WHEN** the endpoint serves the fleet browse
- **THEN** it returns a page of the newest rows and a `next_cursor` when more remain
- **AND** it reports `total_matched` as the not-computed sentinel rather than counting the whole table
- **AND** adding any filter (for example a single `host_id`) makes it report the exact `total_matched` again

#### Scenario: Hash search spans hosts

- **GIVEN** the same binary hash executed on two different hosts
- **WHEN** the client searches by that `hash` with no `host_id`
- **THEN** the response includes the matching process from each host

#### Scenario: Host filter scopes to one host

- **GIVEN** a fleet-wide match set
- **WHEN** the client adds a `host_id` filter
- **THEN** the response contains only that host's matches, using the same endpoint and contract

#### Scenario: Keyset pagination is stable and complete

- **GIVEN** a filtered result set larger than one page
- **WHEN** the client pages through it following `next_cursor` until none is returned
- **THEN** the concatenation of pages is every matching row exactly once, newest-first, with no duplicate or skipped row

#### Scenario: Malformed cursor is rejected

- **GIVEN** a request carrying a cursor that does not decode
- **WHEN** the endpoint processes it
- **THEN** the response status is 400

#### Scenario: An out-of-vocabulary filter value is rejected

- **GIVEN** a request whose `signing` or `exit_reason` value is not in its accepted set
- **WHEN** the endpoint processes it
- **THEN** the response status is 400 and the reader is not queried

### Requirement: Host detail endpoint

The system SHALL expose `GET /api/hosts/{host_id}` returning one host's identity and liveness: the host identifier, the enrollment hostname, the OS product name, OS version, and OS build, the agent version, the source IP recorded at enrollment, the enrollment time, the timestamp of the inventory report that last refreshed identity, the most recent time any event from the host was observed, the count of events seen, and the server-computed agent-health rollup. The endpoint SHALL be authorized by the same host-read action as the host list. An unknown host identifier MUST return 404; a host that has sent events but has no enrollment record MUST still return, with empty identity fields, matching the list endpoint's posture.

#### Scenario: Operator fetches host detail

- **GIVEN** an enrolled host that has sent events and posted an inventory check-in
- **WHEN** the client calls `GET /api/hosts/{host_id}`
- **THEN** the response carries the hostname, OS name/version/build, agent version, source IP, enrolled-at, last-seen, event count, and health rollup for that host

#### Scenario: Unknown host id returns 404

- **GIVEN** a host identifier no host row matches
- **WHEN** the client calls `GET /api/hosts/{host_id}`
- **THEN** the response status is 404

#### Scenario: Never-enrolled host returns empty identity

- **GIVEN** a host that has sent events but has no enrollment record
- **WHEN** the client calls `GET /api/hosts/{host_id}`
- **THEN** the response returns with empty identity fields rather than 404

### Requirement: Host event timeline endpoint

The server SHALL expose `GET /api/hosts/{host_id}/timeline`, gated on the process-read action scoped to the host, returning that host's exec, network-connection, and DNS-query events interleaved in event-time order, newest first. The endpoint SHALL bound results to an event-time window (`from`/`to` in nanoseconds; zero or absent means unbounded on that side) and SHALL accept an optional `type` filter (a comma-separated subset of the supported event classes) and an optional case-insensitive `text` substring match against the event payload, and an optional `chain` filter scoping results to a set of process generations (each given as `pid:pidversion`), so a client can scope the timeline to an alert's process chain. An event matches a generation when its originating pid and kernel pid generation (pidversion) both match, which uniquely identifies the generation across PID reuse that a raw-pid filter would conflate. An event that does not carry a pidversion SHALL match no generation: a missing pidversion is not pidversion 0 (a real kernel generation), so a scope for `(pid, 0)` MUST NOT include events that never carried the field. A malformed `chain` value SHALL be rejected as a bad request. Results SHALL be keyset-paginated with an opaque cursor and SHALL carry the total match count independent of the page, matching the fleet-wide search contract. An unrecognized event type SHALL be rejected as a bad request; a malformed cursor SHALL be rejected as a bad request; and when the archive read surface is not configured the endpoint SHALL return service-unavailable.

#### Scenario: Timeline interleaves the three event classes in time order

- **GIVEN** a host has exec, network-connection, and DNS-query events within a window
- **WHEN** the timeline is requested for that host and window with no type filter
- **THEN** the response lists all three event classes interleaved in descending event-time order
- **AND** it carries the total number of matching events

#### Scenario: Type filter restricts the classes returned

- **WHEN** the timeline is requested with a type filter naming only DNS queries
- **THEN** only DNS-query events are returned and the total reflects that class alone

#### Scenario: Text match filters by payload substring

- **GIVEN** events whose payloads contain a distinctive string (a path, address, or query name)
- **WHEN** the timeline is requested with that string as the text filter
- **THEN** only events whose payload contains the string (case-insensitively) are returned

#### Scenario: Chain scope selects generations by pid and pidversion

- **GIVEN** a host where a pid was reused by more than one process generation across the window
- **WHEN** the timeline is requested with a `chain` filter of `pid:pidversion` generations
- **THEN** only events whose pid and pidversion match one of those generations are returned, so a later process that reused the same pid is excluded
- **AND** an event that omits pidversion is excluded even from a `(pid, 0)` generation, so events that never carried the field are not swept in
- **AND** a malformed `chain` value is rejected as a bad request

#### Scenario: Keyset pagination is stable and complete

- **GIVEN** a window with more matching events than one page
- **WHEN** the timeline is paged through by following the returned cursor
- **THEN** every matching event appears exactly once across the pages in a stable order
- **AND** the last page returns no further cursor

#### Scenario: An unrecognized event type is rejected

- **WHEN** the timeline is requested with a type filter naming an unsupported event class
- **THEN** the request is rejected as a bad request rather than returning an empty result

### Requirement: Host activity histogram endpoint

The system SHALL expose `GET /api/hosts/{host_id}/activity-histogram` accepting a `from`/`to` nanosecond window and returning the count of process starts per time bucket within it, together with the bucket size. The server SHALL derive the bucket size from the window so the number of buckets stays bounded regardless of the window's width. The bucket counts MUST sum to the total number of process starts in the window, and the endpoint SHALL be authorized by the same host-read action as the process tree.

#### Scenario: Bucketed counts cover the window

- **GIVEN** a host with process starts spread across a requested window
- **WHEN** the client calls the activity-histogram endpoint
- **THEN** the response carries per-bucket counts whose sum equals the number of process starts in the window
- **AND** each start is counted in the bucket containing its start time

#### Scenario: Bucket size scales with the window

- **GIVEN** two requests whose windows differ by an order of magnitude
- **WHEN** each response is returned
- **THEN** each derives a bucket size that keeps the bucket count bounded rather than returning one bucket per fixed interval

#### Scenario: Invalid window is rejected

- **GIVEN** a request whose `from` is not before its `to`
- **WHEN** the client calls the endpoint
- **THEN** the response status is 400
