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

- [x] ADR-0010 stateless-server invariant + CLAUDE.md note
- [x] drain-then-shutdown on SIGTERM (`server/httpserver/serve.go` `DrainState` + `RunAndShutdown`); `EDR_SHUTDOWN_DRAIN` config;
  `/readyz` reports 503 while draining
- [x] race-safe first-boot admin seed (loser re-fetches on the email unique-key dup; exactly one row)
- [ ] loser replica does not print the bootstrap token — DEFERRED to PR 4: needs the leader coordinator (there is no token
  re-issue path, so "print only on creation" would strand an operator who misses it; the leader-gated banner is the clean fix)
- [x] `service.instance.id` on the OTel resource (`bootstrap.Init` -> `observability.Options`)
- [x] requirements + scenarios added to `server-availability`; test markers (the stateless requirement is ADR-enforced, no test)

## PR 4: leader coordinator package

- [x] `server/coordination/leader` package (MySQL `GET_LOCK`, crash-safe via connection-scoped locks) + integration tests
- [x] wire retention + process-TTL under `RunIfLeader`; leave processor parallel (SKIP LOCKED); nil coordinator runs directly
- [x] requirements + scenarios added to `server-availability`; test markers
- [x] seed-banner "loser does not print": cmd/main gates the redemption-banner emission on `coordinator.DoOnceIfLeader` (fail-open
  so a missed banner never strands the first operator: both tokens are valid, redeeming one is enough). Loser replicas skip;
  scenario + test added to server-availability.

## PR 5: multi-replica install package + multi-replica integration test

- [x] `packaging/docker-compose-multi-replica.yml` + NGINX + HAProxy configs + install-server.md topology + `task install:multi-replica:up`
- [x] `test/integration/multi_replica_test.go` (SKIP LOCKED, cross-replica session/CSRF, goose lock under concurrent apply)
- [x] boot-time migration advisory lock at the cmd layer (`leader.WithLock` around the schema apply in cmd/fleet-edr-server)
- [x] requirements + scenarios added to `server-availability`; test markers (3 requirements, 4 scenarios)

## PR 6: operations + availability + SLA docs + ADR-0011

- [x] rolling-upgrade runbook; rate-limiter + audit-queue decisions (`docs/operations.md`); stale "CREATE TABLE IF NOT EXISTS"
  migration claims scrubbed in operations.md + install-server.md; godoc pointers added on `iplimiter.go` + audit `async.go`
- [x] availability + SLA docs (`docs/install-server.md`): 99.9% control-plane target, agent-side resilience, MySQL-SPOF + 3 caveats
- [x] ADR-0011 HA architecture (capstone); ADR index (README) updated to list 0009/0010/0011
- [ ] archive this change once every scenario has a marker (post-merge capstone: run `openspec archive add-server-availability`
  after PR 5 + PR 6 land on main; spectrace already reports 286/286 normative scenarios marked)
