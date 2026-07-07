# Tasks

## 1. Move agent health into the host Details popover

- [x] 1.1 Fetch `getHostHealth` inside `HostDetailsPopover` and render an "Agent health" section (rollup pill + per-component conditions) at the top of the popover.
- [x] 1.2 Show an attention dot on the Details trigger only when the rollup is degraded (amber) or unhealthy (red), with a visually-hidden label for assistive tech.
- [x] 1.3 Remove the standalone `HostHealthPanel` component and its render site in `ProcessTree`; scrub the stale "matching HostHealthPanel" comments.

## 2. Drop the self-referential related-alert link

- [x] 2.1 Thread `currentAlertId` from `ProcessTreeView` through `GraphBody` into `ProcessDetail`.
- [x] 2.2 Filter the alert whose page is open out of "Related alerts"; keep every other alert on the process.

## 3. Seat triage in the alert header (layout)

- [x] 3.1 Render `AlertTriageActions` inside the alert breadcrumb row next to the id / severity / title / time; drop the separate actions row.

## 4. Tests + gates

- [x] 4.1 Re-home the two agent-health scenario markers to `HostHeader` tests; cover the dot states (healthy / degraded / unhealthy / unknown) and the reveal-on-demand rollup.
- [x] 4.2 Test that `ProcessDetail` omits the current alert from "Related alerts" and keeps the others.
- [x] 4.3 tsc, vitest, eslint, dashes, prose, openspec validate, spectrace green.
