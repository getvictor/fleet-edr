## Context

Alerts carry `techniques?: string[]` and `rule_id`; `AlertDetail` adds `event_ids: string[]` (the events that triggered the alert). The alert breadcrumb already renders technique badges as `<Link to={/rules/:ruleId}>`. `ProcessTreeView` fetches the host's open + acknowledged alerts into an `alertProcessIds: Set<number>` (keyed by the process DB id, `alert.process_id`) to mark nodes; the hover tooltip is built by the pure `buildNodeTooltip(node)`. `ProcessDetail` fetches the selected process's alerts via `listAlertsByProcessId(node.id)` and renders each. `HostTimeline` rows are archive events carrying `event_id` and an OS `pid` (not the DB process id).

## Goals / Non-goals

**Goals:**

- The technique is visible inline where the analyst investigates: node tooltip, detail panel, timeline row.
- Reuse the breadcrumb's badge + `/rules/:ruleId` link pattern; no new endpoint (every technique is already on the alert).

**Non-goals:**

- No tactic coloring or ATT&CK-navigator layer; just the technique-id badges.
- No new alert/technique fetch shape on the server.

## Decisions

- **Tooltip tags are display-only.** A hover tooltip disappears on mouse-out, so a link inside it is unreachable; the tooltip shows the technique ids as plain badges. The clickable link lives on the detail panel (a click away, stable) and the timeline row. This matches the acceptance criteria ("tooltip and panel show the tags"; "tags link to the rule page") without a dead link in a transient card.
- **The graph keys tags by process DB id.** `ProcessTreeView` already fetches the host alerts; it builds a `techniquesByNodeId: Map<number, string[]>` (deduped technique ids per `alert.process_id`) alongside the existing `alertProcessIds` set, and threads a node's techniques into `buildNodeTooltip`. The panel keys the same way implicitly: it already holds the process's alerts (each with `techniques` + `rule_id`), so it renders per-alert badges directly.
- **The timeline keys tags by event id, not process.** A timeline event carries the OS pid, while an alert keys on the process DB id, and the timeline view deliberately does not load the process tree (#583) that would map one to the other. The honest, available correlation is the alert's triggering `event_ids`: `HostTimeline` fetches the host's alerts (open + acknowledged), pulls each alerting rule's `event_ids` via `getAlertDetail`, and builds a `Map<event_id, {ruleId, techniques}>`; a row whose `event_id` is in the map shows that rule's technique badges. This tags the exact event that fired the technique (the MDE pattern), which is more precise than tagging every row of the process and needs no pid mapping. The detail fetches are bounded by the host's alert count and run only when the timeline view is active.
- **One shared badge component.** A small `TechniqueTags` presentational component renders a technique-id list either as plain badges (tooltip) or as `/rules/:ruleId` links (panel, timeline), so the three sites stay consistent and a future tactic-color change lands in one place.

## Risks / Trade-offs

- [Per-alert `getAlertDetail` fetches in the timeline] -> bounded by the host's alert count (typically a handful) and lazy (only in timeline view); if a host accumulates many alerts this could be several requests, an acceptable cost for the tag overlay and revisited only if it shows up as slow.
- [Timeline tags only the triggering event, not every row of an alerted process] -> a deliberate scope choice driven by the pid-vs-DB-id gap; it is the precise mapping and avoids loading the tree into the timeline. Process-wide tagging would need the server to surface the process pid (or DB id) on the timeline event, a follow-up if wanted.
- [A node with several alerts] -> the tooltip shows the deduped union of all their techniques; the panel shows them grouped per alert (each linking to its own rule), so the per-rule attribution is preserved where the link matters.
