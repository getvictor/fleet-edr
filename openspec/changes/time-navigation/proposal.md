## Why

Investigations need absolute time ranges: the host page offers four fixed relative presets, so anything outside the last 24 hours is unreachable (the client-side tree search silently misses it), and "when did activity spike" has no answer short of eyeballing the tree. Modern time UX (Grafana, Datadog) keeps one compact control at rest rather than a preset row plus a picker. This is story #581 of epic #577, which absorbed #420's histogram + scrubber; the two are one design because they command the same window.

## What Changes

- The host page's segmented preset row is replaced by one compact time control labeled with the active window ("Last 1 hour" or an absolute span). Its popover offers relative quick-picks (15m, 1h, 6h, 24h, 7d) and an absolute from/to picker; arrow buttons shift the active window backward/forward by its own width.
- A new `GET /api/hosts/{host_id}/activity-histogram` endpoint returns process-start counts bucketed over a window (bucket size derived from the window so the bar count stays bounded), a pure GROUP BY over data the tree already reads.
- A histogram strip renders above the tree for the active window; clicking a bucket narrows the window to that bucket, and the time control's label reflects the resulting absolute range.
- Alert deep-links keep their anchored default (a wide window ending at the alert time), satisfying the existing alert-pivot requirement unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `server-rest-api`: ADDED requirement for the activity-histogram endpoint.
- `web-ui`: ADDED requirement "Host page time navigation" (compact control, absolute ranges, shift arrows, histogram scrubbing). The canonical tree-visualization requirement only references "the selected time window" and is untouched, so no collision with the in-flight aggregation delta.

## Impact

- Server (detection context): histogram store query + handler beside the tree route (reader-seam pattern like host detail/health), handler + DB-backed tests.
- UI: new `TimeRangeControl` and `ActivityHistogram` components (+ tests), window-model refactor in `ProcessTree.tsx` (relative/absolute/anchored), `api.ts`/`types.ts` additions.
- No agent or wire-schema changes.
