# 0008. Selective Endpoint Security subscription: BTM for persistence, no broad NOTIFY_OPEN

- Status: Accepted
- Date: 2026-05-29
- Deciders: getvictor

## Context

The system extension's ESF client (`extension/edr/extension/ESFSubscriber.swift`) subscribes to
`ES_EVENT_TYPE_NOTIFY_OPEN` and forwards **every** file open, system-wide, to the agent. PR #299 extended that to
forward every `NOTIFY_CREATE` as well (re-emitted as an `open` event). The deliberate philosophy was "the extension
forwards everything; the server rules decide" so a new write-rule needs no extension re-release.

The two detection rules that consume `open` events both key on a write to a sensitive **target path**:

- `privilege_launchd_plist_write` (T1543.004): a non-platform binary writing `/Library/LaunchDaemons/*.plist`.
- `sudoers_tamper`: a write to `/etc/sudoers` or `/etc/sudoers.d/*`.

This model has a measured cost. On the L5 system-test run (2026-05-29) the unfiltered open/create stream built a large
agent-queue backlog that delayed detection by ~12 minutes (the FIFO backlog the uploader catch-up fix in #300 only
partially absorbs), and the same event-volume pressure feeds the AUTH_EXEC serial-handler stall tracked in #298. `NOTIFY_OPEN`
is the single highest-volume ES event.

We calibrated against industry practice for a top-tier macOS EDR. Apple's guidance, published analysis of commercial
agents, and mature open-source tooling (Red Canary Mac Monitor) converge on a different model than ours:

- **Selective subscription at the source**, not "subscribe broadly, filter in the backend." Commercial sensors do
  on-host selectivity first.
- **The process graph (EXEC/FORK/EXIT) is the backbone**, plus file-*modification* events (CREATE, WRITE, RENAME,
  UNLINK). Broad `NOTIFY_OPEN` is avoided as a telemetry source.
- **Launch-item persistence is detected via `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** (Background Task Management,
  macOS 13+), a high-level event with no underlying syscall, that fires when a LaunchAgent/LaunchDaemon or login item is
  registered.
- Path muting / inverted (allowlist) subscription is Apple's recommended performance **and stability** lever: ESF
  terminates a client that floods or misses AUTH deadlines.

Two ESF mechanics constrain the design and rule out the naive fixes:

1. **`NOTIFY_OPEN` cannot be muted per-event-type.** `es_mute_path_events` / `es_mute_process_events` silently ignore
   `NOTIFY_OPEN` (the call returns success but events keep flowing). So there is no clean "keep the open firehose but mute
   the noise per path." The only levers for OPEN are whole-path muting (which also mutes exec for that path) or not
   subscribing to OPEN.
2. **Target-path muting + inversion is global across event types, and EXEC's target is the executable.** Inverting
   target-path muting to "select only `/Library/LaunchDaemons`" would also mute `AUTH_EXEC` for every exec outside those
   dirs, breaking exec authorization and Application Control. Per-event-type target muting (`es_mute_path_events`) for
   CREATE/WRITE/RENAME avoids this, since those events honor per-event muting (unlike OPEN).

The project targets macOS 13+ (ADR-0002), so BTM events and all muting/inversion APIs are available.

## Decision

The extension moves to **selective, source-side ESF subscription**:

1. **Drop broad `NOTIFY_OPEN`.** It cannot be selectively muted and is not how top EDRs collect file telemetry.
2. **Detect LaunchDaemon / LaunchAgent / login-item persistence via `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**,
   replacing the file-write proxy in `privilege_launchd_plist_write`. BTM is lower-volume and catches drops the
   file-write rule misses (atomic temp-file + rename, `cp` by a platform binary).
3. **For file-tamper rules with no BTM equivalent (`sudoers_tamper`): subscribe to `NOTIFY_CREATE` / `NOTIFY_WRITE`
   (+ `RENAME`) with per-event-type inverted TARGET-path muting scoped to the sensitive directories only.** Never global
   target-path inversion (it would mute `AUTH_EXEC`). Call `es_unmute_all_target_paths` before inverting.
4. **Keep `EXEC` / `FORK` / `EXIT` as the process-graph backbone**, unchanged.

The watched-path set for (3) starts **hardcoded in the extension**, documented as mirroring the rules' target paths. A
server-pushed set (riding the existing Application Control XPC snapshot) is the intended end-state once the set grows;
that is a separate decision, not this ADR.

## Consequences

**Good:**

- Drastically lower event volume: removes the open/create firehose that caused the finding-(a) backlog/latency and feeds
  the #298 exec-stall. ESF-client stability improves (no flood-induced termination).
- More robust persistence detection: BTM fires on launch-item registration regardless of how the plist landed, closing
  the atomic-rename and platform-binary-`cp` gaps `privilege_launchd_plist_write` documents as limitations.
- Aligns with Apple guidance and commercial-EDR practice for a top-tier product.

**Bad:**

- **Reverses the "forward everything; server decides" philosophy for file events.** The extension now encodes which
  target paths matter; a new file-tamper rule on a new path needs an extension change (and re-release) until the
  server-pushed path set lands. This is the coupling #299 deliberately avoided, accepted here for the volume win.
- **BTM fires at registration, not at the raw file-write "drop" moment.** `privilege_launchd_plist_write` deliberately
  caught the drop early because LaunchDaemon activation is often deferred to reboot. Mitigation: optionally retain a
  narrow target-path-muted CREATE/WRITE watch on `/Library/LaunchDaemons` alongside BTM (defense in depth, early-drop +
  robust-registration), or accept registration-time as the primary signal. To be decided during implementation.
- Every step requires VM (L5) validation that exec/auth and each rule still fire; the ESF client code is not
  unit-testable (Xcode-only target).
- New extension code + wire surface: a BTM payload struct, a corpus fixture, and a new/changed server rule keyed on the
  BTM event rather than `open`.

## Alternatives considered

- **Keep broad `NOTIFY_OPEN` and add `es_mute_path`.** Rejected: `NOTIFY_OPEN` is silently ignored by per-event-type
  muting, and whole-path muting would also mute exec for that path. Does not match industry practice.
- **Global target-path inversion to select only the watched dirs.** Rejected: mutes `AUTH_EXEC` (target = the
  executable) → breaks exec authorization and Application Control. The decisive landmine.
- **Forward-everything + backend filtering (status quo).** Rejected: it is the source of the volume/latency/exec-stall
  problems and is not how production sensors are built.
- **Server-pushed watched-path set now.** Deferred, not rejected: it is the right end-state (no coupling, no re-release
  per new path), but it requires wiring the path set through the Application Control snapshot plus dynamic re-muting on
  update. Start with a hardcoded set and migrate.

## References

- #301 (the volume issue this ADR re-scopes), #299 / PR #302 (the create-forwarding change this ADR supersedes the
  direction of), #298 (AUTH_EXEC serial-handler stall), #300 (uploader catch-up).
- L5 system-test run 2026-05-29 (the ~12-minute detection-latency backlog observation).
- `extension/edr/extension/ESFSubscriber.swift`, `extension/edr/extension/ESFSubscriber+FileEvents.swift` (current
  subscription + file-event handlers).
- `server/rules/internal/catalog/privilege_launchd_plist_write.go`, `.../sudoers_tamper.go` (the `open`-keyed rules).
- ADR-0002 "macOS Apple Silicon MVP only" (the macOS 13+ floor that makes BTM + inversion available).
- Apple: [es_mute_path](https://developer.apple.com/documentation/endpointsecurity/es_mute_path(_:_:_:)),
  [es_mute_path_events](https://developer.apple.com/documentation/endpointsecurity/es_mute_path_events(_:_:_:_:_:)),
  [es_invert_muting](https://developer.apple.com/documentation/endpointsecurity/es_invert_muting(_:_:)),
  [ES_MUTE_INVERTED](https://developer.apple.com/documentation/endpointsecurity/es_mute_inverted),
  [WWDC20 Build an Endpoint Security app](https://developer.apple.com/videos/play/wwdc2020/10159/).
- [Apple Developer Forums: NOTIFY_OPEN ignored by per-event muting](https://developer.apple.com/forums/thread/792707).
- [Red Canary Mac Monitor — Endpoint Security overview (BTM_LAUNCH_ITEM_ADD)](https://github.com/redcanaryco/mac-monitor/wiki/5.-Endpoint-Security-Overview).
- [Outflank / Kyle Avery — EDR Internals for macOS and Linux](https://kyleavery.com/posts/edr-internals-macos-linux/).
