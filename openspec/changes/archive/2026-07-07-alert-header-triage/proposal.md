# Alert triage on the alert header, not the process node inspector

## Why

On the alert page (`/ui/alerts/:id`) the process detail panel restated the whole alert: severity, status, title, description, and technique tags, plus acknowledge / resolve / reopen buttons. That is a second copy of what the alert breadcrumb and detail already show one panel over, and the only net-new thing in it is the triage buttons. It also meant a process-optional alert (no process node to click) had no way to change its status from this page at all.

Top EDRs (CrowdStrike Falcon, SentinelOne, Microsoft Defender, Elastic Security) put triage on the detection surface and treat the process node inspector as a reference: it links to related detections rather than restating them and owning their lifecycle. This change follows that pattern.

## What changes

- The alert detail surface on the pivot page gains the alert's current status and its lifecycle controls (acknowledge, resolve, reopen), updating on success. This is now the single triage surface for the alert, so a process-optional alert can finally be triaged from the page.
- The alert detail surface's MITRE technique tags link to the rule documentation page (previously plain badges there; the linked-tag surface was only reachable from the process detail panel).
- The process detail panel no longer restates the alert or owns its lifecycle controls. It lists the process's alerts as compact links to the alert page, keeping the per-alert technique tags that link to the rule doc (unchanged from the inline-mitre-tags behavior).
- The process detail panel's evidence rows align their copy and fleet-search affordances into one trailing icon column, and the fleet-search pivot is an icon button matching the copy button; the panel widens to fit. This is layout only.

## Impact

- Affected specs: `web-ui` (MODIFIED: Alert pivots to the host process tree).
- Affected code: `ui/src/components/ProcessTree.tsx`, `ui/src/components/ProcessDetail.tsx`, new `ui/src/components/AlertTriageActions.tsx`, and their styles/tests.
- No server, wire-format, or persistence change.
