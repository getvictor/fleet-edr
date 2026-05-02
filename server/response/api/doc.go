// Package api is the public surface of the response bounded context.
//
// response owns the agent command queue (commands table). Cross-context
// callers consume response through one interface (Service) covering
// the four operator + agent surfaces:
//
//   - Insert (used by endpoint enroll fan-out + rules policy fan-out
//     via the closure types in their bootstrap.Deps; satisfied here
//     by the Service.Insert method value).
//   - Get / ListForHost / UpdateStatus (consumed internally by the
//     response/internal/{agent,operator} HTTP handlers).
//
// Per ADR-0004 and claude/modular-monolith/phase4.md, response/api
// imports nothing from the project: Command + Status + the request
// shapes are defined here from scratch (no aliases of store types,
// unlike rules/api).
package api
