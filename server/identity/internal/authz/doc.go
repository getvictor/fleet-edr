// Package authz holds the authorization chokepoint every privileged
// handler in detection / rules / response / endpoint / identity calls
// before performing a side effect.
//
// The engine is OPA / Rego under the hood. The Rego module + role
// grant data live at policy/edr.rego and policy/data/*.json and ship
// baked into the binary via embed.FS. cmd/main constructs the engine
// at startup; identity bootstrap exposes it as api.AuthZ for cross-
// context callers, who consume the public boundary in
// server/identity/api/authz.go.
//
// Decisions are sub-millisecond at p99 (gated in CI by bench_test.go)
// and every decision lands an audit row via api.AuditRecorder. Shadow
// mode is the rollout knob: when enabled, the engine evaluates and
// audits the would-be decision but always returns Allow=true so a
// pilot deployment sees the dashboard before enforcement flips on.
//
// Internal to identity. Cross-context callers go through
// server/identity/api.AuthZ.
package authz
