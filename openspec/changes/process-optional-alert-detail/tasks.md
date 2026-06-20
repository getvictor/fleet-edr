# Tasks

## UI

- [x] `ui/src/types.ts`: add optional `techniques?: string[]` to the `Alert` interface (the server already sends it).
- [x] `ui/src/components/ProcessTree.tsx`: derive `isProcessOptionalAlert` from `alertDetail.process_id === 0`; render the description + technique tags under the breadcrumb; honest focus-toggle label for process-optional alerts; render an explicit explanation + opt-in "Show surrounding host activity" in place of the blank canvas, taking precedence over the generic "No processes in this time range" message.
- [x] `ui/src/components/ProcessTree.scss`: styles for the finding-detail panel and the `--info` status state.

## Tests

- [x] `ui/src/components/ProcessTree.test.tsx`: process-optional alert renders description + technique + explanation (not the generic empty message); the opt-in flips out of the focused view; a process-backed alert (`process_id !== 0`) never shows the explanation even when its chain is empty.

## Verification

- [x] `tsc --noEmit`, eslint clean on changed files, full vitest suite green (282 tests).
- [x] Real-tool QA against `task dev:server` (Chrome, edr-dev VM agent data): opened real process-optional `privilege_launchd_plist_write` alerts (agent daemon + synthetic-dropper registrations, `process_id = 0`). Confirmed the description + `T1543.004` tag render, the "not attributed to a single process" explanation replaces the blank canvas, "Show surrounding host activity" widens to the full host tree, and a reload restores the explanation. Regression: a process-backed `suspicious_exec` alert still focuses its chain with no explanation.
