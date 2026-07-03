## ADDED Requirements

### Requirement: Fleet-wide process search endpoint

The system SHALL expose `GET /api/search/processes` returning processes matching a set of composable filters across all hosts, authorized by the process-read action. Supported filters, all optional and combined with AND in the database query (not in application code): `host_id` (exact; absent means every host), `path` (substring), `hash` (exact SHA-256), `uid` (exact), a `from`/`to` fork-time window, `exit_reason` (exact), and `signing` (a derived signer class: `unsigned`, `ad-hoc`, `platform`, `developer-id`, or `signed`). Results SHALL be ordered newest-first by fork time with the row identifier breaking ties, and paginated by an opaque keyset cursor such that paging through the full result set yields every matching row exactly once with no skips or duplicates even as new processes are ingested concurrently. Each response SHALL carry the page of rows, a `next_cursor` when more rows remain (absent or empty on the last page), and `total_matched`, the count of all rows matching the filters independent of pagination. A malformed cursor SHALL be rejected with 400.

#### Scenario: Filters compose across hosts

- **GIVEN** processes on several hosts, some unsigned, some with uid 0
- **WHEN** the client calls `GET /api/search/processes` with `signing=unsigned` and `uid=0`
- **THEN** the response contains exactly the processes that are both unsigned and uid 0, drawn from every host
- **AND** `total_matched` equals that count

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
