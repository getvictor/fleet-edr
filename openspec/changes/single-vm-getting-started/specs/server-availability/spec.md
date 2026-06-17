# Server availability: operator-controlled edge delta

## ADDED Requirements

### Requirement: The default getting-started deployment controls its own edge

The default getting-started deployment SHALL be a single host the operator controls, fronted by a plain reverse proxy that terminates TLS and forwards requests without content inspection, so the authenticated agent ingest and command routes (`POST /api/events`, `POST /api/enroll`, `GET /api/commands`, `PUT /api/commands/*`) are never subjected to a managed web application firewall. The authenticated bearer token, not edge content inspection, SHALL be the control for this machine-to-machine traffic. A deployment whose public edge runs a content-inspecting WAF the operator cannot disable (a managed PaaS edge) SHALL be supported only when the operator exempts those routes from inspection, and the operator documentation SHALL warn that the edge otherwise blocks agent telemetry.

#### Scenario: Agent telemetry carrying attack signatures reaches the server

- **GIVEN** the default single-host topology whose public edge is a plain reverse proxy with no managed ruleset
- **WHEN** an enrolled agent uploads an event batch whose payloads contain attack signatures (a reverse-shell command line and a C2 URL with a SQL-injection fragment)
- **THEN** the request reaches the server and is handled by the ingest endpoint, accepted and persisted, rather than being blocked by the edge before it arrives
