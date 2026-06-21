## ADDED Requirements

### Requirement: Registered authed routes are reachable through the composed router

Every authed API route a bounded context registers SHALL be reachable through the composed outer router with its session-authentication boundary applied. The set of session-protected routes SHALL be derived from what the contexts register rather than maintained as a separate hand-edited allowlist, so a registered authed route can never be omitted from the protected surface. An unauthenticated request to a registered authed route SHALL receive the session middleware's JSON authentication failure, never a fall-through to the single-page-app HTML catch-all.

#### Scenario: A registered authed route is session-protected, not SPA fall-through

- **GIVEN** a bounded context registers an authed API route
- **WHEN** an unauthenticated request hits that route through the composed router
- **THEN** the response is the session-authentication failure as JSON
- **AND** it is not the single-page-app HTML catch-all
