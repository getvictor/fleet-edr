# Alert page cleanup: agent health in the host Details popover, no self-referential alert link, triage in the alert header

## Why

Follow-up polish on the alert page (`/ui/alerts/:id`) after the alert-header-triage and agent-health-reporting work landed. Three rough edges remained:

- Agent health rendered as a standalone "Agent healthy" card that shouted its status even when everything was fine, adding chrome to a page whose job is triaging one alert. Best practice (CrowdStrike Falcon, SentinelOne, Elastic) keeps a healthy host quiet and surfaces health only when it needs attention.
- The process detail panel's "Related alerts" list linked every alert on the process, including the very alert whose page the operator was already on. Linking back to the current page is noise, not a reference.
- The alert's status and its acknowledge / resolve / reopen controls floated on their own row below the description, detached from the alert's identity (id / severity / title / time).

## What changes

- Agent health moves off the standalone panel and into the host header's Details popover. The Details trigger carries an attention dot only when the rollup is not healthy (amber when degraded, red when unhealthy), so a healthy or not-yet-reported host shows no health chrome. Opening the popover reveals the rollup pill plus the per-component conditions (component, status, message, age). The standalone `HostHealthPanel` component is removed.
- The process detail panel's "Related alerts" list omits the alert whose page is currently open, while still listing every other alert on the process. Opened outside an alert context, it lists them all.
- Alert status + triage controls move into the alert header row, next to the alert's id / severity / title / time, the industry-standard seat for a detection's lifecycle controls. This is layout: the triage behavior (the single triage surface, updating on success) is unchanged from alert-header-triage.
- The process tree's "Show system" toggle is hidden when it would change nothing. On an alert chain whose only system-path nodes are the alerted process and its ancestors (kept regardless), the toggle was a dead control; it is now offered only when the current view actually has hidden system processes to reveal.
- The process detail panel's "Kill process" control is disabled (greyed, with the reason shown) once the process has exited, matching how EDR consoles disable a response action whose target is gone. Beyond "you cannot kill a dead process", this is a safety measure: after exit the PID may be reused, so a kill-by-pid could hit an unrelated process.
- The alert list's Host column shows the host's enrollment hostname instead of the raw hardware UUID, matching the host list and the search results. Analysts recognize a hostname, not a UUID; the UUID stays available in the link tooltip. The `useHostNames` host-id -> hostname resolver (previously search-only) moves up to the shared component level so the alert list and search decorate a host identically.

## Impact

- Affected specs: `web-ui` (MODIFIED: The host detail surfaces the health conditions; ADDED: The alert list identifies a host by name; The process detail omits a self-referential alert link; The process tree hides the system-noise toggle when it changes nothing; The kill action is disabled once the process has exited).
- Affected code: `ui/src/components/HostHeader.tsx` (+ `.scss`), `ui/src/components/ProcessTree.tsx` (+ `.scss`), `ui/src/components/ProcessTree.helpers.ts`, `ui/src/components/ProcessDetail.tsx` (+ `.scss`), `ui/src/components/AlertList.tsx`; `ui/src/components/useHostNames.{ts,test.ts}` moved out of `Search/` to the shared component level (import updated in `Search/SearchPage.tsx`); removed `ui/src/components/HostHealthPanel.{tsx,scss,test.tsx}`; comment scrub in `ui/src/components/ActivityHistogram.tsx`.
- No server, wire-format, or persistence change.
