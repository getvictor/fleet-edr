# Tasks

## Extension (VM-gated)

- [ ] `extension/edr/extension/FileTamperSubscriber.swift`: extend the inverted target-path mute set to include `/Library/LaunchDaemons/` (TARGET_PREFIX), `/Library/LaunchAgents/` (TARGET_PREFIX), and per-user `~/Library/LaunchAgents/` (resolved per console user). Re-emit CREATE/WRITE as write-mode `open` events, identical to the sudoers path.
- [ ] Extension unit tests (`EDRExtensionLogicTests`): a write under each launchd directory produces a write-mode `open` event carrying the writer PID + path; a write outside the watched set does not.
- [ ] Live macOS VM validation (edr-dev): register a non-Apple daemon, confirm both the `btm_launch_item_add` event AND the write-mode `open` on the plist arrive, carrying the writer PID. Flag in the PR description (ESF change).

## Server

- [ ] `server/detection/internal/mysql`: query for the nearest-before write-mode `open` event on a given path for a host within a window, returning the writer PID; resolve a PID to its process row id; resolve an executable path to its process row ids.
- [ ] `server/detection/internal/service`: at alert-detail compose, for a process-optional alert derive `related_process_ids` (role-tagged `artifact_writer` / `persisted_executable`) from the linked `btm_launch_item_add` event payload (plist path + executable path). Additive; `process_id` stays 0.
- [ ] `server/detection/internal/operator/handler.go`: add `related_processes` to the alert-detail response.
- [ ] Server tests: synthetic write-mode `open` + BTM events correlate to the expected writer; executable-path correlation finds the persisted binary's runs; no correlation yields an empty set (graceful).

## UI

- [ ] `ui/src/types.ts`: add `related_processes` to `AlertDetail`.
- [ ] `ui/src/components/ProcessTree.tsx`: when `related_processes` is present, seed focus from that set (role-labelled) instead of the empty-state explanation; fall back to the explanation when absent.
- [ ] `ui/src/components/ProcessTree.test.tsx`: a process-optional alert with related processes focuses them; without them, the explanation still shows.

## Docs / spec

- [ ] Note the launchd directories in the detection-rule docs for `privilege_launchd_plist_write` (false-positive sources / provenance).
- [ ] Archive this change after merge (`openspec archive launchd-persistence-provenance`).
