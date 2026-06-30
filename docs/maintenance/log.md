# Schedule audit log

Append one line per scheduled-task run, even when there are no findings. Format:

```
YYYY-MM-DD  <task-name>  <result>  [PR #N | issue #N | no findings]  [notes]
```

`<result>` is one of `done`, `partial`, `skipped`. `partial` means time budget hit before the task was complete; the next run
should pick up where this one left off.

Keep `[notes]` to ONE tight line: the headline outcome (counts, the one or two things changed) plus the PR / issue / branch
reference. Do NOT narrate the run, enumerate verified-clean items, or paste the findings. The full detail belongs in the PR
body; this log is just the audit trail. If it doesn't fit on a line, it's too long.

The log is the audit trail proving the cadence is being honoured. An empty log over a quarter is the signal to drop the schedule
or change the cadence - running tasks with no record is the same as not running them.

---

<!-- entries below, newest at the bottom -->

2026-05-03  doc-accuracy-sweep  partial  no findings  scope: root READMEs + `docs/*.md`; subdirs deferred to next rotation
2026-05-12  best-practices-refresh  done  ADR-gap issue filed  1 demotion, 1 path fix, 4 new unchecked items
2026-05-19  architecture-drift  done  fixed in-PR  boundary heat map clean; cleared stale `PolicyService`/`ActiveCommandPayload`/`ActiveHostsLister` doc refs + a dead `arch-go.yml` allowance; arch-go green
2026-05-19  dead-code-sweep  done  fixed in-PR  staticcheck U1000 clean; deleted dead `PasteManyRuleType` (ts-prune); other 6 ts-prune hits are false positives; 6 UI-pending operator routes not filed
2026-05-28  stale-implementation-references  done  branch `stale-impl-refs-sweep-2026-05-28` @ 0bf831e  rewrote ~50 stale `Phase N` refs + migrated `claude/`->`ai/` refs; in-test/runtime phase stages left as-is
2026-05-28  doc-accuracy-sweep  done  branch `stale-impl-refs-sweep-2026-05-28` (atop #293)  fixed auth-refactor doc rot (OIDC/break-glass), `EDR_*` env drift, dead paths (`agent/wire`, `server/admin`); aspirational `[ ]` items left
2026-06-09  doc-accuracy-sweep  done  branches `doc-accuracy-{broken,renamed}-2026-06-09` + issue #340  fixed `testing-strategy.md` baseline path + ADR-0007 `XPCServer`->`shared/XPCEventServer` rename; rewrote `architecture.md` pre-ADR-0004 layout
2026-06-18  memory-and-claudemd-audit  done  branch `claude-md-audit-2026-06-18`  CLAUDE.md: `uat:e2e`->`test:e2e`, dev server is HTTPS on `0.0.0.0:8088` since #140. MEMORY.md (uncommitted): rewrote decayed #408 dev-DB entry (now merged to main). All other claims/refs verified clean
2026-06-18  todo-fixme-sweep  done  no findings  only marker is upstream's in vendored `server/apidocs/embed/redoc.standalone.js`; `.build/` hits are untracked. Repo clean
2026-06-18  observability-review  done  no code changes; gap tracked by #348  OTel route coverage complete (shared middleware records route-templated `http.server.request.duration`); prometheus policy clean; 2 EDR dashboards healthy (auth dash env default pinned to `prod-render`, minor); 0 alert rules, telemetry-loss/MTTD alerting already in #348
2026-06-18  adr-audit  done  branch `maintenance-adr-tests-2026-06-18`  12 ADRs re-verified in-force; fixed ADR-0007 stale path (`extension/XPCServer.swift`->`shared/XPCEventServer.swift`; the 06-09 fix never merged); advanced ADR-0012 Proposed->Accepted (capability gating shipped) in file + index; README 0004 ->Implemented to mirror its file. Gap list clean (closed #145 covered mysql + MDM-update)
2026-06-18  test-suite-health  done  branch `maintenance-adr-tests-2026-06-18`  full suite green under `-race`; `-count=3 -race` flake-clean (68 pkgs, 0 races); 12 skips (11 legit env/mode guards), deleted 1 hollow perma-skip (`TestAsyncWriter_DrainGlobalDeadline_SpillsToSlog`); slowest test 3.5s (essential); 10+ semantic spot-checks sound. Deleted-test coverage gap filed as #445 (v0.3.0): drain-deadline spill path needs an injectable deadline to test
2026-06-18  claude-config-audit  done  no committed change (`.claude/` gitignored)  pruned 11 dead allow one-offs from settings.local.json (retired VM `10.0.1.137` + old bearer-token API + Fleet-repo paths); ntfy idle hook valid, no `git push` rule; flagged opsx/openspec skill duplication + broad aws/kubectl breadth for review
2026-06-18  ai-review-bot-config-audit  done  no findings  `.coderabbit.yaml`: all 7 path_instruction globs match the tree, all 5 disabled-tool CI refs (go/ts/swift-lint, actionlint, osv-scanner) exist, no deprecated keys, multi-platform globs intact; pre-merge trip-rate N/A (CodeRabbit manual-only here)
2026-06-19  threat-model-and-security-refresh  done  branch `maintenance-threat-model-2026-06-19`  code-driven boundary inventory; threat-model.md: App Control shipped (agent `set_application_control` cmd + detection-content rows), XPC path `extension/`->`shared/XPCEventServer.swift`, named OTLP egress trust assumption; confirmed agent->server is bearer-over-TLS (not mTLS); 5 medium/low gaps (events-at-rest, CSP, mysql-root, harden-runner, CODEOWNERS) unchanged
2026-06-22  consolidation-pass  done  branch `chore/consolidate-logging-into-internal`  merged 87%/94%-duplicated server+agent `logging.go` into `internal/logging` (scrubbed stale arch-go/codecov/sonar refs); baseline dup 1.3%, cognitive-complexity 5282. Top remaining candidates: `bootstrap.go` cog-26, rbac `"db must not be nil"` x5
2026-06-22  consolidation-pass  done  branch `chore/sonar-maintainability-sweep`  Sonar maintainability batch: rbac `"db must not be nil"` x5 to one sentinel + extracted `refuseIfLastActiveAdmin` (SetUserRole back under the complexity cap, dedups the SetUserStatus guard); metrics `"{event}"` x3 to a const. 3 OPEN criticals cleared. Deferred to own PRs: identity `bootstrap.go` cog-26, `dash-lint` cog-19/17
2026-06-30  architecture-anti-patterns  done  branch `architecture-antipatterns-audit-2026-06-30`  first run; 0 code defects. Wrong-layer clean (no handler touches the DB); ADR-0010 clean (all 4 in-process caches carry the safe-to-lose note or are named accepted gaps); typed enums + PrincipalRef so no primitive-obsession bypass; 44 interfaces are idiomatic consumer seams. 2 candidates, 1 dropped at self-review (builder `pendingExits` = intra-batch transient, no cross-request cost). Step-6 delta x1: sharpened premature-abstraction row with the Go interface-placement test (consumer good, producer/grouped bad). Also narrowed the step-2 SQL scan `DELETE`->`DELETE FROM` (dropped 7 HTTP-route false positives/run)

