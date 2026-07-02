## 1. Navigation model

- [x] 1.1 Reorder `LINKS` in `ui/src/components/ui/TopNav.tsx` to Alerts, Hosts, Application control, Coverage; change the Hosts entry's `to` from `/` to `/hosts`
- [x] 1.2 Export a `firstPermittedRoute(can)` helper beside `LINKS` that returns the first entry's route the permission set confers (Coverage's ungated entry guarantees a result)

## 2. Routes

- [x] 2.1 In `ui/src/App.tsx`, mount `HostList` at `/hosts` and render the `/` route as a redirect to `firstPermittedRoute(can)`
- [x] 2.2 Sweep `ui/src` for literal navigations to the host list at `/` (links, `navigate("/")`, catch-all redirects) and retarget them

## 3. Tests

- [x] 3.1 UI tests for root routing: with `alert.read` the root renders the alert list; without it, the first permitted entry (spec markers `alert-list-is-the-home-view/*`)
- [x] 3.2 UI tests for nav order and Hosts active state on `/hosts` and `/hosts/:hostId` (spec markers `alert-first-navigation-order/*`)
- [x] 3.3 Move existing `host-list-is-the-home-view/*` spec markers (unit + e2e) to `host-list-page/*`; update e2e specs that assert the host list at root, and the login e2e that asserts the post-login landing
- [x] 3.4 Run `cd ui && npm test`, `task lint`, and `tools/spectrace check --strict`

## 4. Manual QA

- [x] 4.1 Rebuild the UI bundle, restart the dev server, and verify in Chrome: root lands on Alerts, tab order, Hosts at `/hosts`, host detail deep link with `?alert=` intact, `?next=` round-trip after logout/login
