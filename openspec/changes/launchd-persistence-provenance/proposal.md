# Provenance for LaunchDaemon persistence alerts

## Why

`privilege_launchd_plist_write` ("LaunchDaemon persistence", T1543.004) fires on a `btm_launch_item_add` registration event and classifies the registered executable by its code signing (high precision). But the BTM instigator for a daemon registration is Apple's `smd`, not the actor, so the rule deliberately attributes no process (`process_id = 0`). The result is a process-optional alert with no link to who actually established the persistence. The companion UI change (process-optional-alert-detail) makes that alert legible, but its graph is necessarily empty: there is no related-process data to show.

Industry practice for a persistence detection (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Elastic) is artifact-centric: lead with the persistence object, then anchor on the **responsible process** (the one that wrote the artifact) and its lineage, with the process graph as a scoped pivot into that lineage. We have the artifact (BTM gives the plist path + executable signing) but not the responsible process.

The responsible process is observable: the same write-mode `open` telemetry the `sudoers_tamper` rule already consumes captures who wrote a file under a watched path. We do not watch the LaunchDaemon/LaunchAgent directories yet. Extending the existing dedicated, target-muted file-tamper Endpoint Security client to those directories (the ADR-0008-sanctioned pattern, not the rejected broad-open firehose) gives us the plist writer. Correlating that write to the BTM registration yields the genuinely relevant process lineage to show in the alert.

## What changes

- **Telemetry (extension).** Extend the dedicated file-tamper Endpoint Security client's inverted target-path mute set to also cover `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`, and per-user `~/Library/LaunchAgents/`, re-emitting CREATE/WRITE there as write-mode `open` events (identical mechanism and wire shape to the sudoers coverage). No new event type; no broad-open subscription.
- **Correlation (server).** At alert-detail compose time (off the ingestion hot path, so event ordering and dedup are unaffected), for a process-optional alert correlate the registered plist path to the nearest-before write-mode `open` event on that path for the same host, resolve its PID to a process row, and resolve the registered executable path to that binary's own process runs. Return these as `related_process_ids` on the alert-detail response, each tagged with its role (`artifact_writer`, `persisted_executable`). The alert stays `process_id = 0` for dedup stability; correlation is additive.
- **UI.** When `related_process_ids` is present, the process tree seeds its focus from that set (role-labelled) instead of showing the empty-state explanation. When it is absent (no write captured, binary never ran), the process-optional explanation from the companion change still applies.

## Residual gap (documented, not closed)

Atomic-rename writes (write a temp file, `rename(2)` onto the plist) evade the write-mode-`open` provenance, the same blind spot already documented on `sudoers_tamper` (ESF `NOTIFY_RENAME` is not subscribed; watching rename on the launchd directories is noisy because legitimate installers use it). A sophisticated actor can still land a process-optional alert with no writer; the companion change's explanation + opt-in remains the permanent fallback for that case.

## Impact

- Affected specs: `endpoint-event-collection` (file-tamper coverage extended to the launchd directories), `server-detection-rules-engine` (process-optional provenance correlation + `related_process_ids`), `web-ui` (render related-process context).
- Affected code: `extension/edr/extension/FileTamperSubscriber.swift` (mute-set extension), `server/detection/internal/service` + `server/detection/internal/mysql` (correlation query + alert-detail field), `server/detection/internal/operator/handler.go` (response field), `ui/src/components/ProcessTree.tsx` + `ui/src/types.ts` (render related processes).
- **VM-gated.** The ESF change touches event collection and MUST be exercised on a live macOS VM (system / VM test layer) before RC, per the project testing strategy. This proposal precedes that implementation; implementation lands once a VM validation window is available.
- Depends on: the process-optional-alert-detail change (the UI base this builds on).
