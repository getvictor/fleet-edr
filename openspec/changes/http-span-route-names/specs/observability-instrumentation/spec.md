## ADDED Requirements

### Requirement: HTTP request spans are named by route template

The system SHALL name each inbound HTTP request span `METHOD /route/template` once the request has matched a route, and `METHOD unmatched` when it matched none, so a span name never carries an identifier or a probed path. The span MAY start under its raw path so the route-tier sampler can classify it at span start. Only one instrument SHALL record `http.server.request.duration`, so each request is counted once.

#### Scenario: A matched request's span carries the route template

- **GIVEN** a route registered as `GET /api/hosts/{host_id}`
- **WHEN** the server handles `GET /api/hosts/host-abc`
- **THEN** the request span ends named `GET /api/hosts/{host_id}`

#### Scenario: An unmatched request's span is named unmatched

- **GIVEN** no route matches `/wp-login.php`
- **WHEN** the server handles `GET /wp-login.php`
- **THEN** the request span ends named `GET unmatched`

#### Scenario: Request duration is recorded once per request

- **GIVEN** a meter provider is installed
- **WHEN** the server handles a request
- **THEN** the HTTP instrumentation layer records no `http.server.request.duration` sample of its own, leaving the access log's routed sample as the only one
