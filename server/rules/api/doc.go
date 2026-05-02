// Package api is the public surface of the rules bounded context.
//
// rules owns the server-driven blocklist policy (policies table) and the
// detection rule catalog (eight Go-coded matchers + ATT&CK metadata +
// per-rule documentation). Cross-context callers consume rules through
// three interfaces:
//
//   - PolicyService: GET/UPDATE the active blocklist policy (operator) +
//     ActiveCommandPayload pre-marshaled for agent fan-out (endpoint).
//   - Catalog: enumerate rule metadata for /api/rules and /api/attack-coverage.
//   - ContentService: load executable rules into the detection engine.
//
// Per ADR-0004 and claude/modular-monolith/phase3.md, rules/api may
// import server/store transitively for Event/Process/TimeRange type
// aliases so *store.Store satisfies GraphReader without per-call
// conversion in the rule hot path. Phase 5 redirects those aliases to
// detection/api.
package api
