# 0001. Single Go module with `internal/` for shared code

- Status: Accepted
- Date: 2026-04-19
- Deciders: getvictor

## Context

The repo ships multiple Go binaries: `fleet-edr-server`, `fleet-edr-ingest`,
and `fleet-edr-agent`. They share a non-trivial amount of code: env-variable
parsing, structured-logging bootstrap, OpenTelemetry initialisation, TLS
config with SIGHUP cert reloading, HTTP middleware, shared attribute keys.
They also legitimately need to NOT pull in each other's packages at the
Go import level (the agent must not reach into the server's MySQL store; the
server must not reach into the agent's XPC receiver).

Go offers several layouts for this shape:

1. One module per binary, each with its own `go.mod`.
2. One module with multiple `cmd/*` targets.
3. A mix of modules coordinated via `go.work`.
4. Separate modules with shared helpers published as their own module.

The constraints we're optimising for, in priority order:

- **Dev velocity.** Dependency bumps, cross-cutting refactors, and new
  shared helpers should land in a single PR without `replace` ceremony or
  `go mod tidy` per module.
- **Dep isolation in the built binary.** The agent binary should not contain
  code it doesn't execute. This is about link-time tree-shaking, not about
  `go.sum` hygiene.
- **Architectural clarity.** Someone reading the tree should be able to tell
  server-only code from agent-only code from shared code at a glance.
- **Compatibility with the Go ecosystem.** Tooling (gopls, golangci-lint,
  vulncheck, Sonar) should work without module-specific workarounds.

Observation: `go build` tree-shakes per binary. A package that exists in the
module but isn't imported by `cmd/fleet-edr-agent/main.go` is not linked into
the agent binary. Verified: with MySQL in the shared module's `go.sum`, the
agent binary contains zero strings from `go-sql-driver/mysql`, and
`go list -deps ./agent/cmd/fleet-edr-agent/...` returns no `mysql` package.
This means the "dep isolation" constraint is satisfied by import hygiene,
not by module boundaries.

Observation: every mature Go monorepo of comparable scope uses layout (2).
Kubernetes, Docker, Consul, Vault, Nomad, Terraform, CockroachDB, Prometheus,
Fleet itself -- all ship one module with many `cmd/*` targets and shared
packages under `internal/` or similar. Splitting modules is almost always
driven by external-publishing needs (e.g. `k8s.io/api` as a consumable
sub-module) which don't apply here.

## Decision

Single Go module rooted at `github.com/fleetdm/edr`. Binaries live at
`server/cmd/*` and `agent/cmd/*`. Shared code lives under `internal/`
(language-level encapsulation, prevents external consumption). Enforce the
agent <-> server non-dependency rule at the lint layer via `depguard`
file-scoped rules, so misplaced imports fail CI.

## Consequences

**Good:**

- One `go.mod`, one `go.sum`, one `go mod tidy`. Dep bumps are a single PR.
- Shared helpers are plain packages with no `replace` ceremony.
- `go build ./...` / `go test ./...` / `golangci-lint run ./...` all work
  from repo root against the whole tree.
- Per-binary dep scope is still auditable via
  `go list -deps ./agent/cmd/...` and separate govulncheck CI jobs.

**Bad:**

- The agent <-> server boundary is a lint-time check, not compile-time.
  Someone running `go build` without lint can introduce a cross-boundary
  import. CI catches it, but the local feedback loop is slower than a
  module boundary (which would fail at `go build` time). Mitigated by
  making lint fast and running it in a pre-commit hook.
- Adding a third binary (say a CLI) doesn't get free namespace separation;
  its code has to be placed in the tree under a name that communicates
  scope.

## Alternatives considered

**One module per binary (agent, server, helper-module).** Shared helpers
would need their own module referenced via `replace ../helper` in each
consumer. Every shared helper = a separate `go.mod` + `go.sum` to maintain,
a replace directive per consumer, and a CPD tool like SonarCloud sees the
per-file copy of the shell around each helper call site as duplication. The
claimed benefit (dep isolation) is already delivered by link-time
tree-shaking, so the extra machinery buys nothing real.

**Multiple modules coordinated via `go.work`.** Nicer ergonomics locally
(no `replace` directives, `go.work use ./helper`) but still fails the
"one dep bump per PR" goal and still lets CPD see the per-helper-call-site
duplication. Also requires committing `go.work` and deciding whether to
commit `go.work.sum`, which itself drifts across Go versions. Fine for
genuinely independent modules; overkill for our shape.

**Put shared code at repo root without `internal/` (e.g. `envparse/` as a
package).** Works mechanically but implies external consumability that
isn't intended. `internal/` is a real Go language feature that prevents
packages outside the tree from importing, and that's exactly the contract
we want.

## References

- [Go modules layout guide](https://go.dev/doc/modules/layout)
- [Go `internal/` package rules](https://go.dev/doc/go1.4#internalpackages)
