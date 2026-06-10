# 0008. Selective Endpoint Security subscription: BTM for persistence, no broad NOTIFY_OPEN

- Status: Accepted (amended 2026-05-29 and 2026-05-30; see Amendments below)
- Date: 2026-05-29
- Deciders: getvictor

## Amendment 2026-05-29: BTM attribution ground-truth (edr-dev) and the discriminator / persistence model

The original Decision left two things unspecified that the implementation (#304) then got wrong, both flagged in review (Copilot, Gemini): (1) what the rule discriminates on, and (2) how a persistence alert is persisted when there is no live attacker process. A direct capture on edr-dev (SIP off) of a real `btm_launch_item_add` for `launchctl bootstrap system <plist>` settles both. Raw event:

- `item_type=daemon`, `legacy=true`, `managed=false`, `executable_path=<non-Apple daemon binary>`
- `instigator = /usr/libexec/smd` (`com.apple.xpc.smd`), an Apple platform binary; `app = nil`
- out-of-band on the executable: `codesign` -> ad-hoc / linker-signed, no TeamIdentifier; `spctl -t install` -> rejected (not notarized)

(Full record: `ai/btm-attribution/experiment.md`.)

### Revised decisions

1. **Do NOT gate on the BTM instigator's code-signing.** `launchctl bootstrap` delegates registration to `smd`, so the instigator is an Apple platform binary for _every_ legacy LaunchDaemon registration, attack or not. The instigator is not the attacker, and `app` is nil for this vector. An instigator `is_platform_binary` gate suppresses the canonical attack. (Implementation note: #304 shipped exactly this gate; it must change.)
2. **Discriminate on the registered item.** The signal is the `executable_path`'s signature / notarization, evaluated out-of-band, plus `managed == false` and path. A non-notarized / ad-hoc executable registered as an unmanaged system daemon is high-precision malicious; a Developer-ID + notarized vendor daemon (or `managed == true`) is benign.
3. **Persistence alerts are process-optional.** The BTM event exposes no useful attacker process (only `smd`), and a large class of real persistence has no live process at all (reboot-time registration, an exited dropper, MDM). `alerts.process_id` must be **nullable**; the evidence of record is the item + executable, with any correlated process as enrichment. This supersedes the implicit "every alert has a NOT-NULL process_id" assumption in `server/detection/bootstrap/schema.go`.
4. **The executable must be evaluated out-of-band.** BTM carries code-signing only for the `instigator` / `app` _processes_, never for the to-be-launched executable. The decision input (2) therefore requires a `SecStaticCode` evaluation of `executable_path`. The `codesign` / `spctl` capture confirms the out-of-band classification is clean and decisive. (Superseded by the 2026-05-30 amendment on _where_ it runs: in the **agent**, not the extension, because a SIP-enabled host's extension sandbox denies the read.)

### Correction to the original Decision text

Decision item 2 below claims BTM "catches drops the file-write rule misses (atomic temp-file + rename, `cp` by a platform binary)." The atomic-rename point stands (BTM fires on registration regardless of how the plist landed). The "`cp` by a platform binary" framing is wrong and is withdrawn: BTM does not fire on the `cp`, it fires on the registration, whose instigator is `smd` regardless. Robustness comes from keying on registration + the registered executable, not from observing the copier.

### Implications for the implementation (#304)

- `privilege_launchd_plist_write`: replace the instigator-signing gate with an executable notarization / signature + `managed` decision; drop the `ProcessID == 0` finding path.
- Schema: make `alerts.process_id` nullable (migration + dedup-key NULL handling + insert / query / UI), or carry a separate process-less alert path.
- Add the `SecStaticCode` evaluation of `executable_path` to the BTM payload (new wire field), since the event provides no executable signing inline. (See the 2026-05-30 amendment: the evaluation lands in the agent, not the extension.)
- L5 `scripts/uat/scenarios/attack-runbook/expected.yaml`: the `expect: alert` + `severity: critical` assertion only holds once the discriminator is the executable; align severity (`high`) and re-confirm the expectation against the reworked rule on a notarized build.

## Amendment 2026-05-30: evaluate the executable's signing in the agent, and notarization is not a trust signal

Two refinements to the 2026-05-29 amendment, both forced by what the SIP-on QE VM (edr-qa) showed once the reworked rule ran on a notarized build.

### Ground-truth: the extension cannot read the registered executable on a SIP-enabled host

The 2026-05-29 amendment (revised-decision 4, and the implementation bullet) placed the `SecStaticCode` evaluation of `executable_path` **in the extension**. On edr-qa (SIP on, the pilot-customer simulation) the reworked `privilege_launchd_plist_write` never fired: the extension's `executable_code_signing` was absent because `SecStaticCodeCreateWithPath` failed. The extension is a `sysextd`-managed system extension, and a SIP-enabled host **enforces its sandbox**, which denies the read of the BTM-registered executable (the extension is handed the path but not read access, unlike an `AUTH_EXEC` target, where `SigningInfoFallback` already works because the exec context grants it). edr-dev (SIP off) could not reproduce the miss: with SIP off the sandbox is not enforced, so the same extension code reads the file and the evaluation succeeds. That SIP-on/SIP-off split is the whole finding.

### Revised decision: the agent evaluates the executable's signing, off the ES callback thread

The evaluation moves from the extension to the **agent**, which is an unsandboxed root LaunchDaemon and can read the registered executable on every host (SIP on or off). The agent fills `executable_code_signing` on the `btm_launch_item_add` event before upload, **fill-if-missing and non-destructive**: a pre-populated value (e.g. a synthetic test feed, or a future source that can supply it) is left untouched, and an unreadable executable leaves the field unset so the rule skips (high-precision). The extension now ships `executable_path` and a nil signing.

This is also the safer architecture independent of the sandbox: it lifts signing validation **off the Endpoint Security callback thread**, where a network-touching check (revocation, notarization) could deadlock the extension: the class Gemini flagged. It matches top-tier macOS-EDR practice: signing / reputation work lives in the privileged daemon, off the kernel callback path, never inline on the AUTH/NOTIFY handler. The agent uses the Security framework directly (`SecStaticCode`, `kSecCSNoNetworkAccess`, `anchor apple` for the platform-binary flag) rather than shelling out to `codesign` / `spctl`. The extension's evaluation path (`evaluateExecutableSigning` + `satisfiesAppleAnchor`) is removed so there is a single source of truth. (`agent/codesign`, `agent/enrich`.)

### Notarization is not a trust signal

Revised-decision 2 (2026-05-29) framed the discriminator as "signature / **notarization**". Notarization is withdrawn as a trust input. It is an automated Apple malware scan, not an endorsement (Apple has notarized malware: Shlayer, adload), and it is not checkable network-free in-process on the agent's enqueue path or the ES thread (`SecAssessmentTicketLookup` is not public; `SecAssessment` / Gatekeeper can hit the network). Trust is deterministic and network-free: an Apple **platform binary** (`anchor apple`) or a **team ID on the operator's allowlist** (`EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST`). The `is_notarized` wire field was removed. Notarization / reputation scoring, if ever pursued, belongs in a server-side layer off the hot path. The 2026-05-29 capture's `spctl -t install -> rejected` line remains accurate as ground-truth about that specific binary; it is just no longer a decision input.

## Amendment 2026-05-31: selective subscription implemented (steps 2-3), RENAME deferred

Decision steps 2 and 3 shipped in PR #307 (the implementing PR for #301):

- **`sudoers_tamper` moved to a dedicated file-tamper client (step 2).** A second, NOTIFY-only `es_client_t` (`FileTamperSubscriber`) subscribes to `NOTIFY_CREATE` + `NOTIFY_WRITE`, calls `es_unmute_all_target_paths`, mutes `/etc/sudoers` (target-literal) + `/etc/sudoers.d` (target-prefix), then `es_invert_muting(ES_MUTE_INVERSION_TYPE_TARGET_PATH)` so it observes ONLY those paths. It re-emits each as a write-mode `open` event, so the server rule is unchanged. The inversion lives on this client alone (it has no auth subscriptions), so `AUTH_EXEC` / Application Control on the primary client are untouched (the client-global-inversion landmine this ADR identified). Validated on edr-dev: sudoers create/write fire, a non-sudoers write does not, exec still flows.
- **Broad `NOTIFY_OPEN` + `NOTIFY_CREATE` dropped from the primary client (step 3).** `sudoers_tamper` was the only rule consuming `open`; with it on the file-tamper client, the open/create firehose is removed.
- **`NOTIFY_RENAME` was deliberately NOT subscribed.** The ADR listed it parenthetically, but visudo/sudoedit write via temp-file + atomic rename onto `/etc/sudoers`, so watching rename would fire on every legitimate sudoers edit. The atomic-replace gap stays documented on `sudoers_tamper` (unchanged from before). Closing it cleanly (with a visudo/sudoedit/installer carve-out) is a possible focused follow-up. Step 4 (server-pushed watched-path set) remains future work.

## Context

The system extension's ESF client (`extension/edr/extension/ESFSubscriber.swift`) subscribes to `ES_EVENT_TYPE_NOTIFY_OPEN` and forwards **every** file open, system-wide, to the agent. PR #299 extended that to forward every `NOTIFY_CREATE` as well (re-emitted as an `open` event). The deliberate philosophy was "the extension forwards everything; the server rules decide" so a new write-rule needs no extension re-release.

The two detection rules that consume `open` events both key on a write to a sensitive **target path**:

- `privilege_launchd_plist_write` (T1543.004): a non-platform binary writing `/Library/LaunchDaemons/*.plist`.
- `sudoers_tamper`: a write to `/etc/sudoers` or `/etc/sudoers.d/*`.

This model has a measured cost. On the L5 system-test run (2026-05-29) the unfiltered open/create stream built a large agent-queue backlog that delayed detection by ~12 minutes (the FIFO backlog the uploader catch-up fix in #300 only partially absorbs), and the same event-volume pressure feeds the AUTH_EXEC serial-handler stall tracked in #298. `NOTIFY_OPEN` is the single highest-volume ES event.

We calibrated against industry practice for a top-tier macOS EDR. Apple's guidance, published analysis of commercial agents, and mature open-source tooling (Red Canary Mac Monitor) converge on a different model than ours:

- **Selective subscription at the source**, not "subscribe broadly, filter in the backend." Commercial sensors do on-host selectivity first.
- **The process graph (EXEC/FORK/EXIT) is the backbone**, plus file-_modification_ events (CREATE, WRITE, RENAME, UNLINK). Broad `NOTIFY_OPEN` is avoided as a telemetry source.
- **Launch-item persistence is detected via `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** (Background Task Management, macOS 13+), a high-level event with no underlying syscall, that fires when a LaunchAgent/LaunchDaemon or login item is registered.
- Path muting / inverted (allowlist) subscription is Apple's recommended performance **and stability** lever: ESF terminates a client that floods or misses AUTH deadlines.

Two ESF mechanics constrain the design and rule out the naive fixes:

1. **`NOTIFY_OPEN` cannot be muted per-event-type.** `es_mute_path_events` / `es_mute_process_events` silently ignore `NOTIFY_OPEN` (the call returns success but events keep flowing). So there is no clean "keep the open firehose but mute the noise per path." The only levers for OPEN are whole-path muting (which also mutes exec for that path) or not subscribing to OPEN.
2. **Target-path muting + inversion is client-global, and EXEC's target is the executable.** `es_invert_muting` inverts a mute type (e.g. target-path) across the _entire_ `es_client_t`, and `es_mute_path_events` only mutes by the _process_ path, not the target path, so there is no per-event-type target-path muting on a single client. Inverting target-path muting to "select only `/Library/LaunchDaemons`" on a client that also handles `AUTH_EXEC` would filter `AUTH_EXEC` (whose target is the executable) by that same list, breaking exec authorization and Application Control. The only way to get target-path-selective file monitoring without touching `AUTH_EXEC` is a **dedicated second ES client** for file events (target-path inversion lives on that client alone).

The project targets macOS 13+ (ADR-0002), so BTM events and all muting/inversion APIs are available.

## Decision

The extension moves to **selective, source-side ESF subscription**:

1. **Drop broad `NOTIFY_OPEN`.** It cannot be selectively muted and is not how top EDRs collect file telemetry.
2. **Detect LaunchDaemon / LaunchAgent / login-item persistence via `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**, replacing the file-write proxy in `privilege_launchd_plist_write`. BTM is lower-volume and catches drops the file-write rule misses (atomic temp-file + rename, `cp` by a platform binary).
3. **For file-tamper rules with no BTM equivalent (`sudoers_tamper`): subscribe to `NOTIFY_CREATE` / `NOTIFY_WRITE` (+ `RENAME`) on a DEDICATED second ES client with inverted TARGET-path muting scoped to the sensitive directories only** (`es_unmute_all_target_paths`, mute the watched dirs, then `es_invert_muting` for target-path on that client). Never invert target-path muting on the primary client: it would mute `AUTH_EXEC`.
4. **Keep `AUTH_EXEC` / `NOTIFY_EXEC` / `FORK` / `EXIT` (and BTM) on the primary client**, with no target-path inversion.

This yields **two ES clients**: a primary client (process graph + AUTH_EXEC + BTM, normal muting) and a dedicated file-tamper client (CREATE/WRITE/RENAME, target-path inverted). Two clients is the only way to combine target-path-selective file monitoring with unfiltered exec authorization, and it cleanly separates blocking-auth from high-volume file telemetry, standard practice for mature ESF sensors.

The watched-path set for (3) starts **hardcoded in the extension**, documented as mirroring the rules' target paths. A server-pushed set (riding the existing Application Control XPC snapshot) is the intended end-state once the set grows; that is a separate decision, not this ADR.

## Consequences

**Good:**

- Drastically lower event volume: removes the open/create firehose that caused the finding-(a) backlog/latency and feeds the #298 exec-stall. ESF-client stability improves (no flood-induced termination).
- More robust persistence detection: BTM fires on launch-item registration regardless of how the plist landed, closing the atomic-rename and platform-binary-`cp` gaps `privilege_launchd_plist_write` documents as limitations.
- Aligns with Apple guidance and commercial-EDR practice for a top-tier product.

**Bad:**

- **Reverses the "forward everything; server decides" philosophy for file events.** The extension now encodes which target paths matter; a new file-tamper rule on a new path needs an extension change (and re-release) until the server-pushed path set lands. This is the coupling #299 deliberately avoided, accepted here for the volume win.
- **BTM fires at registration, not at the raw file-write "drop" moment.** `privilege_launchd_plist_write` deliberately caught the drop early because LaunchDaemon activation is often deferred to reboot. Mitigation: optionally retain a narrow target-path-muted CREATE/WRITE watch on `/Library/LaunchDaemons` alongside BTM (defense in depth, early-drop + robust-registration), or accept registration-time as the primary signal. To be decided during implementation.
- Every step requires VM (L5) validation that exec/auth and each rule still fire; the ESF client code is not unit-testable (Xcode-only target).
- New extension code + wire surface: a BTM payload struct, a corpus fixture, and a new/changed server rule keyed on the BTM event rather than `open`.
- **Two ES clients to manage** (lifecycle, subscribe sets, mute configs, and the per-client AUTH deadline budget) instead of one. The split is forced by the client-global inversion constraint above; it is standard ESF-sensor practice but is more moving parts than today's single client.

## Alternatives considered

- **Keep broad `NOTIFY_OPEN` and add `es_mute_path`.** Rejected: `NOTIFY_OPEN` is silently ignored by per-event-type muting, and whole-path muting would also mute exec for that path. Does not match industry practice.
- **Global target-path inversion to select only the watched dirs.** Rejected: mutes `AUTH_EXEC` (target = the executable) → breaks exec authorization and Application Control. The decisive landmine.
- **Forward-everything + backend filtering (status quo).** Rejected: it is the source of the volume/latency/exec-stall problems and is not how production sensors are built.
- **Server-pushed watched-path set now.** Deferred, not rejected: it is the right end-state (no coupling, no re-release per new path), but it requires wiring the path set through the Application Control snapshot plus dynamic re-muting on update. Start with a hardcoded set and migrate.

## References

- #301 (the volume issue this ADR re-scopes), #299 / PR #302 (the create-forwarding change this ADR supersedes the direction of), #298 (AUTH_EXEC serial-handler stall), #300 (uploader catch-up).
- L5 system-test run 2026-05-29 (the ~12-minute detection-latency backlog observation).
- `extension/edr/extension/ESFSubscriber.swift`, `extension/edr/extension/ESFSubscriber+FileEvents.swift` (current subscription + file-event handlers).
- `server/rules/internal/catalog/privilege_launchd_plist_write.go`, `.../sudoers_tamper.go` (the `open`-keyed rules).
- ADR-0002 "macOS Apple Silicon MVP only" (the macOS 13+ floor that makes BTM + inversion available).
- Apple: [es_mute_path](<https://developer.apple.com/documentation/endpointsecurity/es_mute_path(_:_:_:)>), [es_mute_path_events](<https://developer.apple.com/documentation/endpointsecurity/es_mute_path_events(_:_:_:_:_:)>), [es_invert_muting](<https://developer.apple.com/documentation/endpointsecurity/es_invert_muting(_:_:)>), [ES_MUTE_INVERTED](https://developer.apple.com/documentation/endpointsecurity/es_mute_inverted), [WWDC20 Build an Endpoint Security app](https://developer.apple.com/videos/play/wwdc2020/10159/).
- [Apple Developer Forums: NOTIFY_OPEN ignored by per-event muting](https://developer.apple.com/forums/thread/792707).
- [Red Canary Mac Monitor: Endpoint Security overview (BTM_LAUNCH_ITEM_ADD)](https://github.com/redcanaryco/mac-monitor/wiki/5.-Endpoint-Security-Overview).
- [Outflank / Kyle Avery: EDR Internals for macOS and Linux](https://kyleavery.com/posts/edr-internals-macos-linux/).
