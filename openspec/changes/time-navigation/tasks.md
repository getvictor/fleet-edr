## 1. Server

- [x] 1.1 Store method `ActivityHistogram(ctx, hostID, fromNs, toNs)`: derive bucket (window/60, floored to whole seconds, min 1s), GROUP BY over `fork_time_ns` in `[from, to)`, return buckets + bucket size + total
- [x] 1.2 `activity_histogram_handler.go` on the reader-seam pattern (route + gate + 400 on bad window + 503 unwired); bootstrap wiring
- [x] 1.3 Handler tests + DB-backed integration test (sum == total, containment, scaling, 400) with spec markers (`host-activity-histogram-endpoint/*`)

## 2. UI window model

- [x] 2.1 `ui/src/timewindow.ts`: window type (relative w/ optional anchor, absolute), `windowBounds`, `windowLabel`, `shiftWindow`; table-driven tests
- [x] 2.2 Refactor `ProcessTree.tsx` from `rangeIdx` to the window model; preserve `?at=` alert anchoring (spec marker `alert-entry-keeps-its-anchored-window`)

## 3. UI time control

- [x] 3.1 `TimeRangeControl.tsx` (+ scss + tests): at-rest labeled button, popover with relative quick-picks (15m, 1h, 6h, 24h, 7d) and absolute `datetime-local` from/to, shift arrows (spec markers `one-control-at-rest-with-relative-and-absolute-selection`, `shift-arrows-move-the-window-by-its-width`)

## 4. Histogram

- [x] 4.1 `getActivityHistogram` in `api.ts` + types
- [x] 4.2 `ActivityHistogram.tsx` (+ scss + tests): SVG bar strip, accessible button bars, bucket click narrows the window (spec marker `histogram-bucket-click-narrows-the-window`); render above the tree for the active window

## 5. Verification

- [x] 5.1 `go test ./server/detection/...` + integration with `EDR_TEST_DSN`, `cd ui && npm test`, lint/tsc, `task lint:go`, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 5.2 Manual QA on the dev server in Chrome: control popover (relative + absolute), shift arrows, histogram render + bucket click on the seeded QA host, alert deep-link default unchanged

## 6. Docs

- [x] 6.1 CHANGELOG entry under 0.4.0
