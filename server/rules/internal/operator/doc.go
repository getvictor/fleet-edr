// Package operator serves the rules-context operator routes:
//
//	GET  /api/policy             - get the active default policy
//	PUT  /api/policy             - update the active default policy + fan out
//	GET  /api/rules              - list registered rules + their docs
//	GET  /api/attack-coverage    - MITRE ATT&CK Navigator layer
//
// All four are session-gated by cmd/main's wiring (Session + CSRF on
// unsafe methods). The handlers delegate business logic to api.PolicyService
// and api.Lister; this package owns only the HTTP-flavoured concerns
// (body parse, body cap, audit log, error mapping).
package operator
