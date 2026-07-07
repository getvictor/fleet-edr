# Tasks

## 1. Relocate triage to the alert header

- [x] 1.1 Extract `AlertTriageActions` (status pill + acknowledge / resolve / reopen, reauth-wrapped) as its own component.
- [x] 1.2 Render it on the alert detail surface in `ProcessTree`, updating the alert's status locally on success.
- [x] 1.3 Link the alert detail surface's technique tags to the rule doc page via the shared `TechniqueTags`.

## 2. Compact the process detail alerts block

- [x] 2.1 Replace the restated alert card with a compact "Related alerts" list of links to the alert page.
- [x] 2.2 Keep the per-alert technique tags (linked to the rule doc), drop the description and the lifecycle buttons.

## 3. Align the process detail evidence affordances (layout)

- [x] 3.1 Give each evidence row a value + trailing action cluster so copy / search icons line up in one column.
- [x] 3.2 Render the fleet-search pivot as an icon button matching the copy button; widen the panel.

## 4. Tests + gates

- [x] 4.1 Unit-test `AlertTriageActions` (each transition, local callback, failure leaves status unchanged).
- [x] 4.2 Test the header triage path in `ProcessTree` (process-optional alert is triageable from the page).
- [x] 4.3 Update `ProcessDetail` tests: related-alerts links, no triage buttons, no restated description.
- [x] 4.4 tsc, vitest, eslint, dashes, openspec validate, spectrace green.
