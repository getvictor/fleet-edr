## Why

Competitive research across CrowdStrike, SentinelOne, Microsoft Defender, and Elastic (epic #577) shows SOC analysts enter the product alert-first: they live in the alert queue and pivot into hosts for context, while the host list is a fleet-health and inventory surface. Our UI inverts that: the authenticated app lands on the host list and Alerts is the second tab, so the dominant workflow starts one click away from where it should. This is story #578, the cheapest high-impact item of the epic.

## What Changes

- The authenticated application's home view becomes the alert list: navigating to `/` routes to Alerts instead of the host list.
- The host list moves from `/` to `/hosts`; the existing host detail route `/hosts/:hostId` is unchanged, so the Hosts navigation entry highlights for both.
- Top navigation order becomes Alerts, Hosts, Application control, Coverage (was Hosts, Alerts, Application control, Coverage).
- An operator whose permission set does not confer `alert.read` lands on the first navigation entry their permissions do confer, rather than a no-access error on the landing page.
- Existing deep links keep working: `/hosts/:hostId?alert=...&process=...&at=...` and the `?next=` login round-trip are preserved.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `web-ui`: the "Host list is the home view" requirement becomes "Alert list is the home view" with the host list relocated to `/hosts` (its content behavior is unchanged); the "Authenticated entry to the application" requirement's successful-login scenario now routes to the alert list; a permission-aware landing fallback is added for operators without `alert.read`.

## Impact

- `ui/src/App.tsx`: route table (`/` redirect, `HostList` at `/hosts`).
- `ui/src/components/ui/TopNav.tsx`: `LINKS` order and the Hosts entry's `to`.
- Any UI code that navigates to the host list by the literal `/` path.
- UI tests for routing, nav order, and the permission fallback; no server, agent, or wire changes.
