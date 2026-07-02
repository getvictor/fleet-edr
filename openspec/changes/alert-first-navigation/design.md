## Context

The authenticated app currently mounts `HostList` at `/` and lists the nav as Hosts, Alerts, Application control, Coverage (`ui/src/App.tsx`, `ui/src/components/ui/TopNav.tsx`). Analyst-workflow research (epic #577) established alert-first entry as the dominant path. Nav entries are permission-gated by a per-entry read action; Coverage is deliberately ungated, so every authenticated operator has at least one visible entry.

## Goals / Non-Goals

**Goals:**

- `/` lands on the alert list for operators who can read alerts, and on their first permitted nav entry otherwise.
- Host list keeps identical content at `/hosts`; `/hosts/:hostId` unchanged; deep links and `?next=` round-trip preserved.
- One source of truth for nav order and gating shared by the nav bar and the landing redirect, so they cannot disagree.

**Non-Goals:**

- No changes to the alert list itself, the host list content, permissions, or any server behavior.
- No change to #422's in-tree alert-anchored default (separate story in #415).

## Decisions

- **Redirect, not dual-render**: `/` renders a redirect to `/alerts` rather than mounting `AlertList` at both paths, keeping one canonical URL per surface (matches the existing `*` catch-all redirect idiom in `App.tsx`).
- **Landing fallback derives from the nav model**: export the ordered, gated `LINKS` list (or a `firstPermittedRoute(can)` helper next to it) from `TopNav.tsx` and use it for the `/` redirect target. Display order defines fallback order; Coverage's ungated entry guarantees termination. No separate role-to-route mapping is introduced (the spec forbids a UI role map).
- **Hosts tab activation**: the existing `startsWith` active-link logic covers `/hosts` and `/hosts/:hostId` once the entry's `to` is `/hosts`; the root special case for `/` is no longer needed by any entry but stays harmless.

## Risks / Trade-offs

- [Bookmarks to `/` now land on Alerts] → intended behavior change; the host list remains one click away and directly linkable at `/hosts`.
- [Existing tests and e2e specs assert host list at root] → updated in the same PR, including `spec:` markers that move from `host-list-is-the-home-view/*` to the renamed requirement.
- [An operator with zero gated reads] → lands on Coverage (ungated), which is the pre-existing least-privilege surface; no new exposure.
