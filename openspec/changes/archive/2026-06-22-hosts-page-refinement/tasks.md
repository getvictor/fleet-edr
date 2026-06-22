# Refine the hosts page: tasks

## 1. Server

- [x] `server/detection/api/types.go`: add `Hostname` + `OSVersion` to `HostSummary` with `db`/`json` tags; document them as enrollment-sourced and empty for un-enrolled hosts.
- [x] `server/detection/internal/mysql/hosts.go`: `ListHosts` LEFT JOINs `enrollments` on `host_id`, COALESCEs hostname/os_version to `''`; comment the cross-context (shared-DB) join.
- [x] `server/detection/internal/tests/integration_test.go`: `TestListHosts_DecoratesWithEnrollment` seeds an enrollment row + an un-enrolled host and asserts the decoration and the LEFT-not-INNER fallback. Marker on the new server-rest-api scenario.

## 2. UI primitive

- [x] `ui/src/components/ui/StatCard.tsx` (+ `.scss`): `StatCard` ({ value, label, accent }) + `SummaryStrip`; accent enum (`green`/`red`/`neutral`) maps to border tokens, no raw hex.
- [x] `ui/src/components/ui/StatCard.test.tsx`: value/label render + accent-class mapping + strip wrapping.

## 3. Hosts page

- [x] `ui/src/types.ts`: add optional `hostname` + `os_version` to `HostSummary`.
- [x] `ui/src/components/HostList.tsx` (+ `.scss`): drop `PageHeader`; render `SummaryStrip` (online/offline/total via memoised `isOnline`); columns `Host | Platform | Status | Events | Last seen` with hostname-over-UUID (UUID fallback), platform fallback dash, right-aligned events.
- [x] `ui/src/components/HostList.test.tsx`: hostname-vs-UUID fallback, platform fallback, summary counts, row navigation, empty/error states. Marker on the new web-ui scenario.

## 4. Coverage-page reuse

- [x] `ui/src/components/AttackCoverage.tsx` (+ `.scss`): replace inline `.attack-coverage__summary`/`__metric` with `SummaryStrip` + `StatCard`; delete the dead SCSS.
- [x] `ui/src/components/AttackCoverage.test.tsx`: pin the three summary stat cards (none existed before).

## 5. Verification

- [x] `go test -tags=integration ./server/detection/internal/tests/` (ListHosts JOIN tests) green.
- [x] `cd ui && npx vitest run` green for changed files; `tsc --noEmit` + `eslint` clean.
- [x] `cd ui && npm run build` compiles SCSS + bundles.
- [x] `openspec validate hosts-page-refinement --strict`; spectrace `--strict`; dash + markdown-prose lints all clean.
- [x] Real dev-server QA in Chrome (summary counts 3/2/5, hostname+UUID cell, un-enrolled UUID-only fallback, Platform column, right-aligned events, row-click navigation). Caught and fixed an Events left-align bug (class outranked by `.table td`).
