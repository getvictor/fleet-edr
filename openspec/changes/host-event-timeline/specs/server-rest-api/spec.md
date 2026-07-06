## ADDED Requirements

### Requirement: Host event timeline endpoint

The server SHALL expose `GET /api/hosts/{host_id}/timeline`, gated on the process-read action scoped to the host, returning that host's exec, network-connection, and DNS-query events interleaved in event-time order, newest first. The endpoint SHALL bound results to an event-time window (`from`/`to` in nanoseconds; zero or absent means unbounded on that side) and SHALL accept an optional `type` filter (a comma-separated subset of the supported event classes) and an optional case-insensitive `text` substring match against the event payload, and an optional `pids` filter (a comma-separated list of process ids) scoping results to events whose originating pid is in the set, so a client can scope the timeline to an alert's process chain. A `pids` value that is not a list of non-negative integers SHALL be rejected as a bad request. Results SHALL be keyset-paginated with an opaque cursor and SHALL carry the total match count independent of the page, matching the fleet-wide search contract. An unrecognized event type SHALL be rejected as a bad request; a malformed cursor SHALL be rejected as a bad request; and when the archive read surface is not configured the endpoint SHALL return service-unavailable.

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

#### Scenario: Pids filter scopes to the alert chain

- **GIVEN** a host with events from several processes
- **WHEN** the timeline is requested with a `pids` filter naming a subset of those processes
- **THEN** only events whose originating pid is in the set are returned, and the total reflects that subset
- **AND** a `pids` value that is not a list of non-negative integers is rejected as a bad request

#### Scenario: Keyset pagination is stable and complete

- **GIVEN** a window with more matching events than one page
- **WHEN** the timeline is paged through by following the returned cursor
- **THEN** every matching event appears exactly once across the pages in a stable order
- **AND** the last page returns no further cursor

#### Scenario: An unrecognized event type is rejected

- **WHEN** the timeline is requested with a type filter naming an unsupported event class
- **THEN** the request is rejected as a bad request rather than returning an empty result
