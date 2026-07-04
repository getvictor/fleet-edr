## ADDED Requirements

### Requirement: Fleet-wide connection and DNS search

The search page SHALL offer connection and DNS search modes alongside process search, selectable from the page and reflected in the URL so each mode is bookmarkable. Connection mode SHALL query the fleet-wide connection search endpoint for a remote address; DNS mode SHALL query the fleet-wide DNS search endpoint for a domain. Because those endpoints require an artifact value, each event mode SHALL prompt for the address or domain and SHALL NOT issue a search until one is supplied. Event results SHALL render as a table showing, per event, the time, the host (its enrollment hostname when known, else the host identifier), the originating process, and the mode-specific detail: for a connection the direction, protocol, and remote address with port; for a DNS query the query type and the resolved addresses. As with process search, the page SHALL show the total number of matches and, when more results remain, a control that loads and appends the next page, and SHALL let the operator narrow either mode to a single host.

#### Scenario: Connection mode lists fleet-wide connections to an address

- **GIVEN** the connection search endpoint returns matching connections across more than one host
- **WHEN** the operator opens the search page in connection mode with a remote address in the URL
- **THEN** the page shows a row per connection with the host, the process, and the remote address and port
- **AND** the page shows the total number of matches

#### Scenario: DNS mode lists fleet-wide lookups of a domain

- **GIVEN** the DNS search endpoint returns matching queries across more than one host
- **WHEN** the operator opens the search page in DNS mode with a domain in the URL
- **THEN** the page shows a row per query with the host, the process, the query type, and the resolved addresses

#### Scenario: An event mode prompts for the artifact before searching

- **GIVEN** the search page is opened in connection or DNS mode with no artifact value in the URL
- **WHEN** the page renders
- **THEN** it prompts for the remote address or domain and issues no search request

#### Scenario: Load more appends the next page of events

- **GIVEN** an event result set larger than one page, so the response carries a next cursor
- **WHEN** the operator activates the load-more control
- **THEN** the next page's events are appended to the table using the cursor
- **AND** when no cursor remains the load-more control is not shown

### Requirement: Network artifact search pivots

The process detail panel's network section SHALL offer a "search fleet" pivot on each remote address and on each DNS query name. Activating the remote-address pivot SHALL open the search page in connection mode pre-filtered to that address; activating the DNS pivot SHALL open the search page in DNS mode pre-filtered to that query name.

#### Scenario: Pivoting from a remote address searches connections fleet-wide

- **GIVEN** the process detail panel shows a network connection to a remote address
- **WHEN** the operator activates that connection's search pivot
- **THEN** the UI opens the search page in connection mode filtered to that remote address across all hosts

#### Scenario: Pivoting from a DNS query searches lookups fleet-wide

- **GIVEN** the process detail panel shows a DNS query for a domain
- **WHEN** the operator activates that query's search pivot
- **THEN** the UI opens the search page in DNS mode filtered to that domain across all hosts
