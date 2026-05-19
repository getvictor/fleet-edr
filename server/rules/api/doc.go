// Package api is the public surface of the rules bounded context.
//
// rules owns the detection rule catalog (Go-coded matchers + ATT&CK metadata
// + per-rule documentation) and the application-control policy/rule store.
//
// Two interfaces are designed for consumption by other bounded contexts:
//
//   - Lister: enumerate rule metadata for /api/rules and /api/attack-coverage.
//   - RuleProvider: load executable rules into the detection engine.
//
// ApplicationControlStore is also exposed here, but solely so the rules-context
// REST handler and tests can depend on the contract instead of importing the
// internal package (ADR-0004's bounded-context import rule). No other context
// consumes it today; it lives in api/ for ADR-conformance, not cross-context
// use.
//
// Per ADR-0004, rules/api re-exports detection/api types
// (Event/Process/TimeRange/GraphReader/Finding/NullRawJSON) as type
// aliases so the catalog rule files can implement Rule.Evaluate
// without importing detection/api directly. The alias is a deliberate
// design choice; arch-go.yml names it explicitly.
package api
