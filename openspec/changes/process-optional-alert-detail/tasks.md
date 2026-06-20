# Tasks

## UI

- [x] `ui/src/types.ts`: add optional `techniques?: string[]` to the `Alert` interface (the server already sends it).
- [x] `ui/src/components/ProcessTree.tsx`: derive `isProcessOptionalAlert` from `alertDetail.process_id === 0`; render the description + technique tags under the breadcrumb; honest focus-toggle label for process-optional alerts; render an explicit explanation + opt-in "Show surrounding host activity" in place of the blank canvas, taking precedence over the generic "No processes in this time range" message.
- [x] `ui/src/components/ProcessTree.scss`: styles for the finding-detail panel and the `--info` status state.

## Tests

- [x] `ui/src/components/ProcessTree.test.tsx`: process-optional alert renders description + technique + explanation (not the generic empty message); the opt-in flips out of the focused view; a process-backed alert (`process_id !== 0`) never shows the explanation even when its chain is empty.

## Verification

- [x] `tsc --noEmit`, eslint clean on changed files, full vitest suite green (282 tests).
- [ ] Real-tool QA against `task dev:server`: open the LaunchDaemon-persistence alert (the agent's own daemon registration produces one), confirm the description + technique render, the explanation replaces the blank canvas, the opt-in widens to the host tree, and a reload preserves the explanation. (Pending; run before merge.)
