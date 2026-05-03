// Package api is the public surface of the rules bounded context.
//
// rules owns the server-driven blocklist policy (policies table) and the
// detection rule catalog (eight Go-coded matchers + ATT&CK metadata +
// per-rule documentation). Cross-context callers consume rules through
// three interfaces:
//
//   - PolicyService: GET/UPDATE the active blocklist policy (operator) +
//     ActiveCommandPayload pre-marshaled for agent fan-out (endpoint).
//   - Lister: enumerate rule metadata for /api/rules and /api/attack-coverage.
//   - RuleProvider: load executable rules into the detection engine.
//
// Per ADR-0004, rules/api re-exports detection/api types
// (Event/Process/TimeRange/GraphReader/Finding/NullRawJSON) as type
// aliases so the catalog rule files can implement Rule.Evaluate
// without importing detection/api directly. The alias is a deliberate
// design choice; arch-go.yml names it explicitly.
package api
