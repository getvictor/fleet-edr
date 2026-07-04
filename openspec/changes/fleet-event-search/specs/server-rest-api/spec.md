## ADDED Requirements

### Requirement: Fleet-wide connection and DNS search endpoints

The system SHALL expose `GET /api/search/connections` and `GET /api/search/dns`, each authorized by the process-read action, returning events from the archive matching an artifact value across all hosts: connections whose remote address equals the requested value, and DNS queries whose query name equals it. Each endpoint SHALL accept the artifact value (required; an absent or empty value is a 400), an optional `host_id` scoping the search to one host, and a `from`/`to` window over ingest time. Results SHALL be ordered newest-first, paginated by an opaque keyset cursor over `(timestamp_ns, event_id)` such that paging the full set yields every matching event exactly once with no skips or duplicates, and each response SHALL carry the page of events, a `next_cursor` when more remain, and `total_matched`. A malformed cursor SHALL be rejected with 400.

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

#### Scenario: Missing artifact value is rejected

- **GIVEN** a request with no artifact value
- **WHEN** the endpoint processes it
- **THEN** the response status is 400

#### Scenario: Keyset pagination is stable and complete

- **GIVEN** a matching set larger than one page
- **WHEN** the client pages through it following `next_cursor` until none is returned
- **THEN** the concatenation of pages is every matching event exactly once, newest-first, with no duplicate or skipped event
