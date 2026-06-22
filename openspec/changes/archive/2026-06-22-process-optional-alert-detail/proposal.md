# Explain process-optional alerts in the host process tree

## Why

A process-optional detection (one that keys on an artifact rather than a live process, e.g. `privilege_launchd_plist_write` / "LaunchDaemon persistence") opens into a completely blank process graph with no on-screen explanation. The alert link lands on `/ui/hosts/<host>?alert=<id>&process=0&at=<ts>`; the process tree defaults to focus mode and filters the forest down to the alerted process's chain, but with `process_id = 0` that chain is empty, so the entire forest is hidden and the analyst sees a silent blank canvas. They cannot tell whether the EDR is broken, the data was lost, or nothing happened. The forensic detail that explains the alert (the registered executable and the LaunchDaemon plist path, the MITRE technique) is carried on the alert but never rendered in this view.

The fix is not to fall back to the full host tree (that dumps thousands of unrelated processes). It is to make the process-optional case a first-class, explained state: render the finding's detail regardless of graph state, and replace the silent blank canvas with an explicit explanation plus an opt-in to widen to the surrounding host activity.

## What changes

- The process tree page renders the alert's **description and MITRE technique tags** under the breadcrumb, for every alert. This is the primary "what and why" surface and the only meaningful content for a process-optional alert whose graph is intentionally empty.
- For a process-optional alert (`process_id === 0`) in focus mode, the page renders an **explicit explanation** ("This detection isn't attributed to a single process...") in place of the blank canvas, with an **opt-in control** to widen to the full host tree. The forest is never auto-expanded.
- The focus toggle label is honest for process-optional alerts ("Focused on alert" rather than the misleading "Focused on chain").
- The explanation derives from the alert's `process_id` and description, both reloaded from the alert on every navigation, so it survives a page reload (it does not depend on a non-persisted toggle).

This is a UI-only change: the server already carries the alert's description, severity, rule id, MITRE techniques, and `process_id` on the existing alert-detail response. No server, agent, wire, or persistence change.

## Scope

This change closes the "blank canvas, no explanation" bug. It does NOT populate the graph with the processes genuinely related to the detection (the process that wrote the persistence artifact, or the persisted executable's own runs); for `privilege_launchd_plist_write` the registration instigator is Apple's `smd`, not the actor, and the writer-provenance telemetry does not exist yet. Surfacing related processes is a separate follow-up (provenance correlation + the file-tamper subscriber extension) tracked alongside this change.

## Impact

- Affected spec: `web-ui` (the "Alert pivots to the host process tree" requirement gains a process-optional scenario).
- Affected code: `ui/src/components/ProcessTree.tsx`, `ui/src/components/ProcessTree.scss`, `ui/src/types.ts` (adds `techniques` to the `Alert` interface), `ui/src/components/ProcessTree.test.tsx` (new).
