## 1. Shared badge

- [x] 1.1 `ui/src/components/TechniqueTags.tsx` (+ test): render a technique-id list as plain badges or as `/rules/:ruleId` links (a `ruleId` prop toggles linking); empty list renders nothing.

## 2. Node tooltip

- [x] 2.1 `ui/src/components/node-tooltip.ts`: `buildNodeTooltip(node, techniques?)` -> `NodeTooltip` gains `techniques?: string[]`; unit test.
- [x] 2.2 `ui/src/components/ProcessTree.tsx`: build `techniquesByNodeId: Map<number, string[]>` from the fetched alerts alongside `alertProcessIds`; thread it into `TreeInteractions` and the `buildNodeTooltip` hover call; render the tooltip's techniques (display-only) in the hover card.

## 3. Detail panel

- [x] 3.1 `ui/src/components/ProcessDetail.tsx`: render each alert's technique ids as `/rules/:rule_id` link badges in the alert entry (+ test).

## 4. Timeline rows

- [x] 4.1 `ui/src/components/HostTimeline.tsx`: build a `Map<event_id, {ruleId, techniques}>` from the host's alerts (open + acknowledged) and their `getAlertDetail` event ids; a row whose `event_id` is in the map renders the technique link badges (+ test).

## 5. Verification

- [x] 5.1 `cd ui && npm test`, `npm run lint`, tsc, `vite build`, `tools/spectrace check --strict`, `openspec validate --all --strict`.
- [x] 5.2 Manual QA on the dev server: hover an alerted node, open its panel, and view the timeline for a host with an alert; confirm the tags render and the panel/timeline tags link to the rule page.

## 6. Docs

- [x] 6.1 CHANGELOG entry under 0.4.0.
