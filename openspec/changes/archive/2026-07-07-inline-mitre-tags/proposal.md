## Why

We store MITRE ATT&CK technique ids per alert and render them only on the alert breadcrumb, so the technique mapping is invisible during the actual investigation, the walk of the process tree and the event timeline. Every leading EDR surfaces the technique inline on nodes and events (MDE's bold technique rows, SentinelOne's tactic-colored graph indicators). This is #585 (epic #577, wave 3): show the tags where the analyst already is.

## What Changes

- **Process graph**: an alerted node's hover tooltip shows its technique tags (display-only, since a hover card cannot host a link), so an analyst reads the technique while walking a chain without opening the panel.
- **Process detail panel**: each alert entry shows its technique tags as badges that link to the rule's documentation page (`/rules/:ruleId`), the same target the breadcrumb badges use. The panel already fetches the process's alerts, techniques and all.
- **Host timeline**: a row whose event triggered an alert carries that alert's technique tags, linked to the rule page. The correlation is by event id (an alert's triggering `event_ids`), the precise "this event fired technique T…" mapping, since a timeline event carries the OS pid, not the alert's process DB id.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `web-ui`: ADDED requirement "Inline MITRE technique tags".

## Impact

- `ui/src/components/node-tooltip.ts` (+ test): tooltip carries techniques.
- `ui/src/components/ProcessTree.tsx`: builds a node-id -> techniques map from the alerts it already fetches, threads it to the tooltip; the tooltip render shows the tags.
- `ui/src/components/ProcessDetail.tsx` (+ test): per-alert technique badges linking to the rule page.
- `ui/src/components/HostTimeline.tsx` (+ test): fetches the host's alert triggering-event ids + techniques and tags matching rows.
- No server, agent, or wire change: every technique id is already on the alert payload.
