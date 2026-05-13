// Package operator serves the rules-context operator routes:
//
//	GET  /api/rules              - list registered rules + their docs
//	GET  /api/attack-coverage    - MITRE ATT&CK Navigator layer
//
// Both routes are session-gated by cmd/main's wiring (Session + CSRF on
// unsafe methods). The handlers delegate business logic to api.Lister;
// this package owns only the HTTP-flavoured concerns (response shaping,
// error mapping).
package operator
