# Server availability rollout tasks

Six PRs at ~1000 changed lines each, per `ai/migrations/v0.1.0-execution-plan.md`. Dependency shape is a diamond: the migration
stack (PR 1 -> 2) and the HA-foundation stack (PR 3 -> 4) run in parallel from main, converge at PR 5, and PR 6 lands last.

## PR 1: goose runner + ADR-0009 + pilot contexts (response, endpoint)

- [x] Add `github.com/pressly/goose/v3` dependency
- [x] `server/migrations/runner` package (`Up`, per-context table name) + tests
- [x] response: `migrations/00001_initial.sql` + `embed.go`; `bootstrap.ApplySchema` delegates to runner; delete `schema.go`
- [x] endpoint: `migrations/00001_initial.sql` + `embed.go`; `bootstrap.ApplySchema` delegates to runner; delete `schema.go`
- [x] ADR-0009 (migrations via goose); ADR-0005 Bad-list updated; `docs/best-practices.md` §10 checked
- [x] `server-availability` spec slug with the versioned-migrations requirement + 2 scenarios; runner test markers

## PR 2: convert identity + detection + rules + standalone migrate CLI

- [x] identity, detection, rules: `migrations/00001_initial.sql` + `embed.go`; delegate; delete `schema.go`
- [x] retire the legacy `applyAdditiveAlters` runner in detection (its ALTERs are already folded into the CREATE TABLE)
- [x] `cmd/fleet-edr-migrate` standalone CLI + smoke test
- [x] OpenSpec sync gate satisfied by the spec/best-practices update (the gate passes on any `openspec/` change), not the
  `[no-behavior-change]` opt-out

## PR 3: ADR-0010 stateless + drain-then-shutdown + concurrent-boot safety

- [ ] ADR-0010 stateless-server invariant + CLAUDE.md note
- [ ] drain-then-shutdown on SIGTERM (`server/httpserver/serve.go`); `EDR_SHUTDOWN_DRAIN`
- [ ] race-safe first-boot admin seed; loser replica does not print the bootstrap token
- [ ] `service.instance.id` on the OTel resource (`server/bootstrap/bootstrap.go`)
- [ ] requirements + scenarios added to `server-availability`; test markers

## PR 4: leader coordinator package

- [ ] `server/coordination/leader` package (MySQL `GET_LOCK`) + unit + integration tests
- [ ] wire retention + process-TTL under `RunIfLeader`; leave processor parallel (SKIP LOCKED)
- [ ] requirements + scenarios added to `server-availability`; test markers

## PR 5: multi-replica install package + multi-replica integration test

- [ ] `packaging/docker-compose-multi-replica.yml` + NGINX + HAProxy configs + install-server.md topology
- [ ] `test/integration/multi_replica_test.go` (SKIP LOCKED, cross-replica session/CSRF, goose lock under concurrent apply)
- [ ] boot-time migration advisory lock at the cmd layer
- [ ] requirements + scenarios added to `server-availability`; test markers

## PR 6: operations + availability + SLA docs + ADR-0011

- [ ] rolling-upgrade runbook; rate-limiter + audit-queue decisions (`docs/operations.md`)
- [ ] availability + SLA docs (`docs/install-server.md`)
- [ ] ADR-0011 HA architecture; `ha-architecture.md` header cites it
- [ ] archive this change once every scenario has a marker
