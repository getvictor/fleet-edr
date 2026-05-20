# Schedule audit log

Append one line per scheduled-task run, even when there are no findings. Format:

```
YYYY-MM-DD  <task-name>  <result>  [PR #N | issue #N | no findings]  [notes]
```

`<result>` is one of `done`, `partial`, `skipped`. `partial` means time budget hit before the task was complete; the next run
should pick up where this one left off.

The log is the audit trail proving the cadence is being honoured. An empty log over a quarter is the signal to drop the schedule
or change the cadence - running tasks with no record is the same as not running them.

---

<!-- entries below, newest at the bottom -->

2026-05-03  doc-accuracy-sweep  partial  scope: root-level READMEs + `docs/*.md` (subdirs deferred to next rotation)
2026-05-12  best-practices-refresh  done  1 demotion (ATT&CK mapping → [~] pending v19 re-validation), 1 path fix (observability), 4 new unchecked items, 1 ADR-gap issue filed
2026-05-19  architecture-drift  done  boundary heat map clean (every cross-context import lands on `<other>/api` + sanctioned testkit/testdb test-only paths). Cleared one drift cluster in this PR: stale `PolicyService` / `ActiveCommandPayload` / `ActiveHostsLister` doc references in `rules/api`, `rules/bootstrap`, `detection/bootstrap` and a dead `**.rules.api` allowance for `endpoint.internal` in arch-go.yml (endpoint does not import rules.api; the cited type was never landed). No god-structs, no test-fixture drift, no cross-context FKs, no migration-ordering issues. ADR-0004 still describes intent. arch-go green.
2026-05-19  dead-code-sweep  done  Go: staticcheck -checks=U1000 across `./server/...`, `./agent/...`, `./internal/...` — zero findings. TS: `npx ts-prune` flagged 7 entries; 1 genuinely dead (`PasteManyRuleType` type alias in `ui/src/components/ApplicationControl/pasteInference.ts`, never imported) — deleted; the other 6 are `(used in module)` style-only false positives on intentionally exported foundations (`MILLISECONDS_PER_SECOND`/`SECONDS_PER_MINUTE`/`MINUTES_PER_HOUR` constants composed into `MILLISECONDS_PER_*`, `Process` interface as base of `ProcessNode` + field of `ProcessDetail`, `UseReauthRetry` hook return type, `ButtonSize` prop union) — left as-is. Config: every field in `server/config` + `agent/config` has at least one external reader. Routes: all 54 registered HTTP routes reach a ui/agent/test client; six are operator-surface routes (`GET /api/audit-events`, `GET /api/enrollments`, `POST /api/enrollments/{host_id}/{revoke,rotate}`, `GET /api/v1/app-control/host-groups`, `GET /api/v1/app-control/host-groups/{id}`) with tests but no production UI consumer yet — out of scope for the sweep (UI follow-up), not filed.

