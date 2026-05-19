// Package api is the public surface of the rules bounded context.
//
// rules owns the detection rule catalog (Go-coded matchers + ATT&CK metadata
// + per-rule documentation) and the application-control policy/rule store.
// Cross-context callers consume rules through three interfaces:
//
//   - Lister: enumerate rule metadata for /api/rules and /api/attack-coverage.
//   - RuleProvider: load executable rules into the detection engine.
//   - ApplicationControlStore: read/write app-control policies, rules, host
//     groups, and assignments (consumed by rules' own REST handler and tests).
//
// Per ADR-0004, rules/api re-exports detection/api types
// (Event/Process/TimeRange/GraphReader/Finding/NullRawJSON) as type
// aliases so the catalog rule files can implement Rule.Evaluate
// without importing detection/api directly. The alias is a deliberate
// design choice; arch-go.yml names it explicitly.
package api
