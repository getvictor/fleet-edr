## ADDED Requirements

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
