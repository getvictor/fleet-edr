## Context

`ProcessTree.tsx` models time as an index into four fixed presets, anchored at `now` or the alert's `?at=`; the tree fetch takes `from`/`to` ns. There is no absolute selection, no way to move the window, and no activity overview. #420's histogram was merged into this story because the scrubber and the picker command the same window state.

## Goals / Non-goals

**Goals:**

- One at-rest control; every way of setting the window (preset, absolute picker, shift arrows, histogram click) flows through one window model that the tree, the histogram, and the label all read.
- Histogram counts are cheap (single GROUP BY) and honest (buckets sum to the window's total).

**Non-goals:**

- No brush-to-zoom (belongs to the flat timeline story #583, where drag-select has a row surface).
- No URL persistence of arbitrary absolute windows beyond the existing `?at=` anchor (bookmarkable windows can ride #583).
- No split-by-alert or exec/exit series in the histogram v1; the endpoint shape leaves room to add series later.

## Decisions

- **Window model**: `{ kind: "relative", ms, anchorNs? } | { kind: "absolute", fromNs, toNs }`. Alert entry stays a relative window anchored at the alert time (preserving the alert-pivot requirement's wide default); shifting or bucket-clicking converts to absolute. One `windowBounds(window, nowMs)` helper derives `from`/`to` for every consumer.
- **Histogram counts process starts** (`fork_time_ns` in `[from, to)`), not tree-overlap rows: "when did activity spike" is a question about starts, the GROUP BY needs no join, and the tree's overlap predicate would double-count long-lived processes into every bucket.
- **Bucket size = window / 60, floored to whole seconds** (minimum 1s), computed server-side and returned, so the client renders whatever it gets and the bar count stays bounded by construction.
- **Endpoint via a reader seam** (`ActivityHistogramReader`, `registerHistogramRoutes`), the same co-located route + gate + handler pattern as host detail and host health, gated on the host-read action.
- **Absolute picker uses native `datetime-local` inputs**: keyboard-friendly, no dependency, and the popover stays small. The control's at-rest label reads "Last N" for relative windows and a compact absolute span otherwise.
- **Histogram is a hand-rolled SVG bar strip** (D3 is already the page's idiom); bars are buttons with accessible labels ("14:05 to 14:06, 37 process starts") so scrubbing is testable and keyboard-usable.

## Risks / Trade-offs

- [A 7d window over the 2000-row tree cap shows a truncated tree] -> pre-existing truncation behavior (#423 banner covers honesty); the histogram is server-aggregated so it stays correct even where the tree truncates, which is exactly when the scrubber is most useful.
- [datetime-local granularity is minutes] -> fine for investigation entry; second-precision comes from histogram clicks.
