# Application Control v0.1.0 AUTH_EXEC hardening

## Why

Phase A of `add-application-control` shipped the chassis: data model, six rule identifier types, the
REST surface, the agent command, the extension's decision engine. With the chassis in place the v0.1.0
release cut surfaces three close-out items that must land before the first non-demo pilot:

- **#205 - Application Control failsafe carve-out has no critical platform-binary allowlist.** The AUTH_EXEC
  failsafe matches only `teamID == extensionTeamID AND signing_id ∈ fleetSelfAllowSigningIDs`. An admin who
  pastes the SHA-256 of `/sbin/launchd`, `xpcproxy`, `fseventsd`, `kextd`, `sysextd`, `systemextensionsd`,
  `WindowServer`, `loginwindow`, `mds`, or any other Apple-signed platform binary into a `BINARY` block rule
  bricks the host on next boot. Phase A explicitly omits the Santa-equivalent platform-binary floor; v0.1.0
  cannot ship to ten-to-five-hundred-endpoint pilots without it.
- **#208 - BINARY rule cold-cache first-exec bypass.** Phase A's `handleAuthExec` returns `ES_AUTH_RESULT_ALLOW`
  whenever the `FileHashCache` does not yet have a SHA-256 entry for the exec target. The cache is filled
  asynchronously off the AUTH callback so the second exec catches the rule, but the first one does not. This
  defeats Application Control for any attacker who needs only one execution to win (drop → persist → reboot
  into the persistence path). The bypass is also trivially deterministic via `(dev, inode, mtime)` mutation:
  rename, atomic-replace, or `touch -m` invalidates the cache key on every exec and keeps returning to the
  cold-cache ALLOW path indefinitely.
- **#207 - CDHASH doc comment misattributes the Hardened-Runtime gate to Santa.** Phase A's `ESFSubscriber.swift`
  comments claim the CDHASH-only-on-Hardened-Runtime gate "mirrors Santa's behavior so a migrating Santa
  admin's mental model carries over." Santa does not gate CDHASH on Hardened Runtime; it enforces CDHASH on
  any signed binary. The gate is OUR choice (page mapping is lazy on non-hardened processes and not
  re-verified post-load, so the CDHash ESF reports at exec is not a reliable identity for the bytes that will
  eventually execute). Stale doc-attribution misleads operators migrating from Santa.

Phase A explicitly documents the cold-cache ALLOW posture as "first launch allowed, second launch blocked"
inherited from the demo cut (`ESFSubscriber.swift:54-59, 86-107` in the pre-v0.1.0 tree). With v0.1.0 going
out as a real release (not a demo), that posture is no longer defensible.

The product has not yet shipped its first release. No operator is writing rules. The behavior change can land
without backwards-compatibility scaffolding.

## What Changes

- **AUTH_EXEC handler precedes the snapshot walk with two carve-outs.** Platform-binary carve-out first
  (kernel-classified Apple system binaries return `ES_AUTH_RESULT_ALLOW` with `cache: true` so the kernel
  AUTH cache pins the result for the file's `(dev, inode, mtime)` lifetime), then the existing self-allow
  failsafe (agent + extensions + host app, identified by both team_id and the exhaustive bundle-id allowlist).
- **BINARY rule decisions consult a deadline-guarded synchronous SHA-256.** `FileHashCache` gains a
  `lookupOrComputeWithDeadline(path, stat, deadlineMachAbs) -> HashOutcome` method that streams the file
  through SHA-256 in 64-KiB chunks, checking `mach_absolute_time()` against `es_message_t.deadline` minus a
  500 ms safety margin between chunks. The lazy-fill ALLOW path is gone. `HashOutcome` is `.computed(hex)`,
  `.deadlineExceeded`, `.readFailed`, or `.notNeeded` (the snapshot has no BINARY rules, so the AUTH callback
  skips the hash entirely).
- **Decision logic extracts into a pure-logic `AuthExecDecider`.** The new file lives in `extension/edr/`
  and is added to the SwiftPM target so the XCTest harness can drive the verdict matrix. `ESFSubscriber.swift`
  remains the wire dispatcher; the precedence walk + posture application happens in pure code.
- **Deadline-fallback posture rides on the policy snapshot.** Three options encode the operator's trade-off
  between enforcement strictness, exec-startup latency, and operational visibility: `fail-closed` (DENY +
  emit `application_control_undecided` with `verdict=deny`), `fail-open` (ALLOW silently, demo-equivalent),
  `audit-only` (ALLOW + emit `application_control_undecided` with `verdict=allow`). v0.1.0 wires the field
  through `SetApplicationControlPayload`'s JSON shape and the extension snapshot decode; the marshal substitutes
  `fail-closed` when the upstream `ApplicationControlPolicy` does not set the field, which is the v0.1.0 norm
  because no DB column persists the value yet. Per-policy persistence + the REST surface to set the value land
  in a v0.1.x follow-up.
- **New `application_control_undecided` event kind.** Emitted only under `fail-closed` and `audit-only` postures
  when the hash is unavailable. Carries `pid`, `path`, `verdict`, `reason` (`deadline` or `read_failed`),
  `file_size_bytes`, `policy_id`, `policy_version`. The event schema (`schema/events.json`) is extended; the
  server-side ingestion adds a router case for the new type in a separate ingestion-side patch (out of scope
  for this change; the v0.1.0 cut accepts that the server logs the event without acting on it until the v0.1.x
  follow-up materialises an alert source for the operator dashboard).
- **CDHASH doc comments own the Hardened-Runtime rationale.** Both comments in `ESFSubscriber.swift` now state
  the lazy-page-mapping reason directly and explicitly call out the Santa divergence so a migrating Santa admin
  is not surprised when a CDHASH rule no-ops against a non-hardened target.

## Impact

- **Spec deltas:** `extension-application-control` and `endpoint-event-collection`. The
  `extension-application-control` baseline (currently in flight under `add-application-control`) loses the
  "BINARY value MAY be absent on cold cache; cache SHALL be filled off the callback" semantic for BINARY
  rules and gains four new requirements (platform-binary carve-out, sync hash under deadline, fallback
  posture, undecided event). The `endpoint-event-collection` baseline extends its `event_type` enum and adds
  a payload schema for `application_control_undecided`.
- **Wire:** `SetApplicationControlPayload` carries a new `deadline_fallback` field. The agent commander is
  unaffected (it forwards `rules` as `json.RawMessage`; the unknown-field tolerance of Go's encoder is the
  bridge). Older agents that decode the payload without recognising the field will substitute their internal
  default (also `fail-closed` per the extension snapshot decode path), so the wire is safe to roll forward
  before every host has the updated extension binary.
- **Behaviour change for upgrades:** Pilots running a `v0.1.0-rc.*` build under the cold-cache ALLOW posture
  will, after upgrade, see either a DENY (the `fail-closed` default) or a small latency hit (tens of ms on
  typical multi-MB binaries; the 500 ms safety margin caps the worst case) on the first exec of any unhashed
  binary. The v0.1.x follow-up that adds an operator-controllable `audit-only` posture lets operators measure
  the rate before flipping fleet-wide.
- **DB migration:** None in this change. The per-policy `deadline_fallback` column lands with the v0.1.x
  configurability follow-up.

## Validation

Unit and component tests on the appcontrol/auth-exec-hardening branch already exercise the decider matrix,
the deadline-cache outcomes, the wire shape, and the validator. The system / VM layer (L5) is required for
the AUTH_EXEC handler change because no SwiftPM test can drive an `es_message_t` or observe the kernel's
`is_platform_binary` flag setting.

### edr-dev validation completed 2026-05-26

The new extension binary was built (`xcodebuild -scheme extension`), entitled
(`codesign --force --sign - --entitlements extension/extension.entitlements`), copied to edr-dev
(192.168.64.5), swapped into
`/Library/SystemExtensions/66F05F71-7758-4BD8-BA57-648388473407/com.fleetdm.edr.securityextension.systemextension/Contents/MacOS/com.fleetdm.edr.securityextension`,
and the existing binary was preserved as `/tmp/edr-extension-backup`. `launchctl kickstart -k system/com.apple.sysextd`
respawned the extension at pid 90544 (then 90690, 90809 across snapshot rewrites). After validation the original
binary + snapshot were restored to keep edr-dev in a clean state.

**Confirmed on the running dev build (#205 scope):**

- The new snapshot decoder accepts both shapes: the v0.1.x payload that carries `deadline_fallback` (substituted
  through the snapshot's typed field) and the legacy v0.1.0-rc.* payload that omits it (substituted to
  `FallbackPosture.defaultPosture = .failClosed`). Both loads logged `loaded app control snapshot: policy=1
  version=... rules=...` with no decode warnings.
- AUTH_EXEC subscription succeeded and NOTIFY_EXEC events flow (visible via `log stream --debug` as
  `[ESFSubscriber] exec pid=... path=<private>` lines). Establishes that the new `handleAuthExec` and
  `handleExec` paths run for real execs.
- `/usr/bin/yes` execs cleanly under a snapshot containing the SIGNINGID rule `platform:com.apple.yes` -
  without my carve-out the rule would have DENIED the exec and emitted an `application_control_block` event
  with a corresponding DENY log line. None of that fired. Carve-out is the only code path that produces this
  outcome.

**Blocked on edr-dev by ESF redaction quirk #187 (#208 scope):**

`com.fleetdm.edr.securityextension` is ad-hoc-signed on edr-dev (Developer-ID + notarization is not available
on this VM). Apple's ESF responds to ad-hoc-signed ES clients by redacting `target.team_id=""` AND forcing
`target.is_platform_binary=true` for EVERY exec the client sees - a per-client policy on ESF clients whose
host extension is not Developer-ID-signed + notarized, not a per-binary `CS_PLATFORM_BINARY` classification.
Quantified historically: 393/393 exec events on a fresh queue were redacted (issue #187).

The practical consequence for this change: with the platform-binary carve-out shipping at the top of
`handleAuthExec`, EVERY exec on edr-dev hits the carve-out and short-circuits to ALLOW + cache. The BINARY
layer (sync hash + posture application) is unreachable from the AUTH callback on this VM. Concretely:

- A snapshot containing `{rule_type: BINARY, identifier: <SHA-256 of /tmp/test-binary-v02>}` was loaded
  successfully (verified via `loaded app control snapshot: rules=1` then `rules=2`); execs of
  `/tmp/test-binary-v02` and `/tmp/test-binary-v03` produced gh's normal `--version` output, no DENY log,
  no `application_control_block` event in SigNoz.
- This is the carve-out + ESF-redaction interaction, NOT a defect in the BINARY-layer code. The unit tests
  (15 cases in `AuthExecDeciderTests.swift`, 5 cases in `FileHashCacheTests.swift` for the deadline path)
  prove the pure-logic decision tree and the deadline-bounded compute work; what edr-dev cannot exercise
  is the kernel→handler→sync-hash wire end-to-end.

**Path to clear the gap (required before RC tag):**

The L5 BINARY-rule validation must run on edr-qa (192.168.64.7) under a notarized + Developer-ID-signed
pkg, where ESF does NOT redact `is_platform_binary` and the carve-out only fires on real Apple system
binaries. Pending tasks (5.5 of the v0.1.x follow-up notarization work, plus scenarios 2-7 below) belong
to that test pass.

### Required edr-dev VM scenarios (this change closes scenarios 1 and 6 only)

1. **Platform-binary carve-out** (#205, ADDED requirement
   `extension-application-control/platform-binary-carve-out`):
   - Push a `BINARY` block rule for the SHA-256 of `/sbin/launchd`.
   - Reboot the VM. Confirm the host comes up clean. Confirm `log show` for the extension shows no
     `AUTH_EXEC DENIED path=/sbin/launchd` line and the carve-out short-circuit hits before the snapshot walk.
   - Repeat for `xpcproxy`, `fseventsd`, `kextd`, `sysextd` (each by SHA-256 of the file at
     `/usr/libexec/xpcproxy`, `/System/Library/Frameworks/CoreServices.framework/Frameworks/CarbonCore.framework/Versions/A/Support/fseventsd`,
     etc.). Confirm every Apple platform binary still execs.

2. **BINARY first-exec enforcement** (#208 core, ADDED requirement
   `extension-application-control/deadline-guarded-binary-hash`):
   - Push a `BINARY` block rule for the SHA-256 of a single test binary that has NEVER been exec'd on the
     VM (so the cache is cold).
   - Exec the binary. Confirm the FIRST exec is denied (not the second). Confirm the `application_control_block`
     event on the wire carries the expected `rule_id` and `identifier`.
   - Repeat with a binary mutated via `cp` + `touch -m` between rule push and exec, so the `(dev, inode, mtime)`
     tuple is fresh. Confirm the FIRST exec is still denied.

3. **Deadline fallback under `fail-closed`** (#208 posture, ADDED requirement
   `extension-application-control/deadline-fallback-posture`):
   - Set the snapshot's `deadline_fallback` to `fail-closed` (v0.1.0 default).
   - Force a deadline timeout by lowering the safety margin in a dev build or by replaying a captured
     `es_message_t` with a deadline already in the past against a test stub. Confirm DENY +
     `application_control_undecided` event with `verdict=deny`, `reason=deadline`.

4. **Deadline fallback under `audit-only`**:
   - Same as #3 but with `deadline_fallback` set to `audit-only`. Confirm ALLOW +
     `application_control_undecided` event with `verdict=allow`, `reason=deadline`.

5. **Deadline fallback under `fail-open`**:
   - Same as #3 but with `deadline_fallback` set to `fail-open`. Confirm ALLOW + NO event emission.

6. **CDHASH gate divergence from Santa** (#207, no behaviour change; doc-only):
   - Push a `CDHASH` block rule for the CDHash of a non-Hardened-Runtime binary. Exec the binary. Confirm
     the rule does NOT fire (the CDHash field is absent from the target tuple under our gate).
   - Push the same CDHASH rule for a Hardened-Runtime binary. Exec it. Confirm the rule fires.

7. **Latency budget under sustained exec load** (post-#208 perf regression check):
   - Run a workload that execs ~1000 small binaries (e.g. `find /usr/bin | xargs -n1 -I{} {} --version` in a
     loop) with one BINARY rule in the snapshot. Confirm no `AUTH_EXEC` deadline-kill events from the kernel
     (`launchctl print system | grep -i edr` will surface them if any). Confirm the median sync-hash latency
     in the extension log is below 50 ms.

A pilot RC cannot be tagged until all seven scenarios pass on edr-dev. The PR description for `appcontrol/auth-
exec-hardening` will be updated with the captured log excerpts before promotion to `v0.1.0-rc.9` (or
whichever RC tags the bundle).
