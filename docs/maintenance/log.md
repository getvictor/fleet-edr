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

