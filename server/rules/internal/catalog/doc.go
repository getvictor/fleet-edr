// Package catalog holds the eight Go-coded detection rules + the
// RegistryOptions allowlist surface. Rules satisfy api.Rule and consume
// api.GraphReader (a narrow read interface over the process graph) at
// evaluation time. Adding a new rule means adding one .go file here +
// updating registry.go to register it.
//
// Long-term the catalog migrates to YAML / Sigma per
// claude/modular-monolith/plan.md "Long-term direction" #1; phase 3
// keeps the catalog as Go.
package catalog
