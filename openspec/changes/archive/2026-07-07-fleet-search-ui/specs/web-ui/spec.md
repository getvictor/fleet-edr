## ADDED Requirements

### Requirement: Fleet-wide search page

The UI SHALL provide a search page, reachable from a navigation entry gated on the process-read action, that queries the fleet-wide process search endpoint. The page SHALL derive its active filters from the URL query string so it is bookmarkable and so a pivot is a link, and SHALL render the results as a table showing, per process, the fork time, the host (its enrollment hostname when known, else the host identifier), the process name, the parent, the command line, the user, the code-signing verdict, and the exit reason. The page SHALL present the active filters as removable chips and SHALL let the operator add a filter for host, path, hash, uid, or signing verdict. Because results are keyset-paginated, the page SHALL show the total number of matches and, when more results remain, a control that loads the next page and appends it rather than replacing the current rows. Activating a result row SHALL open that host's process tree anchored at the matching process.

#### Scenario: Search renders matches with a total and host names

- **GIVEN** the process search endpoint returns matching processes across more than one host
- **WHEN** the operator opens the search page with a filter in the URL
- **THEN** the page shows a row per match with the host's name, the command line, and the signing verdict
- **AND** the page shows the total number of matches

#### Scenario: Removing a chip drops that filter

- **GIVEN** the search page displayed with a path filter and a signing filter active as chips
- **WHEN** the operator removes the path chip
- **THEN** the path filter is dropped from the URL and the results reflect the remaining filters

#### Scenario: Load more appends the next page

- **GIVEN** a result set larger than one page, so the response carries a next cursor
- **WHEN** the operator activates the load-more control
- **THEN** the next page's rows are appended to the table using the cursor
- **AND** when no cursor remains the load-more control is not shown

#### Scenario: A result row opens the host tree at the process

- **GIVEN** the search results are displayed
- **WHEN** the operator activates a row
- **THEN** the UI navigates to that host's process tree anchored at the matching process's time

### Requirement: Host page search pivots

The process detail panel SHALL offer a "search all hosts" pivot next to each artifact the fleet-wide search can filter on: the path, the SHA-256 hash, the user, and the code-signing verdict. Activating a pivot SHALL open the search page pre-filtered by that artifact. Artifacts the endpoint cannot filter (the signing identity and team identifier) SHALL remain copy-only without a pivot, so no pivot leads to an unfilterable search.

#### Scenario: Pivoting from a hash searches the fleet

- **GIVEN** the process detail panel is displayed for a process with a SHA-256 hash
- **WHEN** the operator activates the hash's search pivot
- **THEN** the UI opens the search page filtered to that hash across all hosts

#### Scenario: Unfilterable artifacts have no pivot

- **GIVEN** the detail panel shows a signing identity and team identifier
- **WHEN** the panel renders
- **THEN** those rows offer copy but no search pivot
