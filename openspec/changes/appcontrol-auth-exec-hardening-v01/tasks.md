# Application Control v0.1.0 AUTH_EXEC hardening tasks

## Status (2026-05-26)

Implementation shipped on the `appcontrol/auth-exec-hardening` branch as a single PR (commit 898b085).
Unit / component coverage is green (104 swift tests, the touched Go suites, golangci-lint, xcodebuild for
the extension target). The L5 (System / VM) validation matrix in `proposal.md` is the gate before this
change can be archived and the v0.1.0-rc.* tag rotated.

## 1. Platform-binary carve-out (#205)

- [x] 1.1 Add the platform-binary short-circuit at the top of `ESFSubscriber.handleAuthExec`:
  `if target.is_platform_binary { es_respond_auth_result(ALLOW, cache: true); return }`. Order matters: it
  must run BEFORE the existing self-allow failsafe and BEFORE the snapshot walk so the kernel cache pins
  the result for the file's `(dev, inode, mtime)` lifetime.
- [x] 1.2 Update the handler doc comment to enumerate the two carve-outs (platform binary first, then
  self-allow) plus the precedence walk in their respective order.
- [x] 1.3 L5 (edr-dev) validation: under a snapshot containing the SIGNINGID rule `platform:com.apple.yes`,
  exec'd `/usr/bin/yes` against the dev-built extension (pid 90544). Without the carve-out the rule would
  have DENIED + emitted `application_control_block`; the actual run produced no DENY log and no event in
  SigNoz, which is the only outcome consistent with the carve-out firing. See `proposal.md` "edr-dev
  validation completed 2026-05-26" for the full audit trail.
- [ ] 1.4 L5 (edr-qa) validation under a notarized pkg: push BINARY rules for `/sbin/launchd`,
  `/usr/libexec/xpcproxy`, `fseventsd`, `kextd`, `sysextd`. Reboot the VM. Confirm no DENY in the extension
  log and every Apple platform binary still execs. Required because on edr-dev ESF redaction forces
  `is_platform_binary=true` on every exec, which makes the platform-vs-non-platform discrimination
  unobservable. See `proposal.md` scenario 1.

## 2. Deadline-guarded sync SHA-256 (#208 core)

- [x] 2.1 Add `FileHashCache.lookupOrComputeWithDeadline(path, stat, deadlineMachAbs) -> HashOutcome`.
  Internally streams 64-KiB chunks through `SHA256()` checking `mach_absolute_time()` between chunks against
  `deadlineMachAbs - safetyMarginNs`. `safetyMarginNs = 500_000_000` (500 ms) so the post-hash work
  (snapshot lookup, kernel respond, optional event/notification emit) plus a page-in stall margin fits
  inside the kernel deadline.
- [x] 2.2 Cache writes only on `.computed` outcomes. `.deadlineExceeded` and `.readFailed` leave the cache
  empty so the next exec retries. TOCTOU re-stat guard is reused from the existing `computeSHA256`.
- [x] 2.3 Wire the deadline variant into `handleAuthExec`. Pass `msg.deadline` (the
  `es_message_t.deadline` field) through. Gate the call on `!snapshot.binaryRules.isEmpty` so the hash
  compute is skipped entirely when no BINARY rule could fire (`.notNeeded` outcome).
- [x] 2.4 XCTest coverage in `FileHashCacheTests`: `.computed` on first call, cache hit on second call,
  `.deadlineExceeded` when deadline is in the past, `.readFailed` on missing file, `.readFailed` on
  TOCTOU inode mismatch.
- [ ] 2.5 L5 (edr-qa) validation under a notarized pkg: push a BINARY block rule for a fresh test binary
  (cold cache); confirm the FIRST exec is denied. Repeat with a `(dev,inode,mtime)`-mutated binary. NOT
  validatable on edr-dev because ESF redaction forces every exec to hit the platform-binary carve-out
  before the BINARY layer runs (#187). Confirmed empirically on 2026-05-26: a snapshot containing only a
  BINARY rule for `af07f42d...` (gh's SHA-256) loaded cleanly but execs of `/tmp/test-binary-v02` and
  `/tmp/test-binary-v03` ALLOWed through the carve-out. See `proposal.md` scenario 2 and the validation
  audit.

## 3. Pure-logic decider extraction

- [x] 3.1 New `extension/edr/extension/AuthExecDecider.swift`. Exposes `FallbackPosture` enum
  (`failClosed` / `failOpen` / `auditOnly`), `HashOutcome` enum (associated `String` for `.computed`,
  plus `.deadlineExceeded`, `.readFailed`, `.notNeeded`), `AuthTuple` struct (cdhash / signingIDPrefixed
  / teamID), `AuthDecision` enum (`.allow`, `.allowWithUndecidedAudit(reason)`,
  `.deny(rule, matchedIdentifier)`, `.denyWithUndecidedAudit(reason)`), and `decideAuthExec(...)` as the
  precedence walker.
- [x] 3.2 Add the new file to `Package.swift`'s `sources:` list so the SwiftPM target compiles it (and so
  the XCTest target can import the types via `@testable import EDRExtensionLogic`).
- [x] 3.3 `ESFSubscriber.handleAuthExec` rewritten as a thin wire: read deadline, build tuple, compute or
  skip hash, call `decideAuthExec`, dispatch the returned `AuthDecision`. `walkPrecedence` and the nested
  `AuthTuple` / `PrecedenceMatch` types are deleted (their roles move into the decider).
- [x] 3.4 XCTest coverage in `AuthExecDeciderTests`: 15 cases covering (3 postures × 3 hash outcomes ×
  4 precedence layers) plus precedence-order tie-breakers and non-PROTECT enforcement no-op.

## 4. Fallback posture wiring (#208 posture)

- [x] 4.1 Add `FallbackPosture` enum + `IsValidFallbackPosture` + `DefaultFallbackPosture` constant +
  `DeadlineFallback` field on `ApplicationControlPolicy` + `DeadlineFallback` field on
  `SetApplicationControlPayload` in `server/rules/api/types.go`. Marshal substitutes
  `DefaultFallbackPosture` (`fail-closed`) when the policy's value is empty.
- [x] 4.2 Add `deadlineFallback: FallbackPosture` to `ApplicationControlSnapshot` + `deadlineFallback`
  Optional to `ApplicationControlDocument` in `extension/edr/extension/ApplicationControlStore.swift`.
  `makeSnapshot` substitutes `.defaultPosture` (`.failClosed`) when the document's value is nil.
- [x] 4.3 Go tests in `app_control_wire_test.go`: default substitution, per-posture passthrough, JSON key
  pin (`deadline_fallback`), validator coverage.
- [ ] 4.4 L5 (edr-qa) validation under a notarized pkg: drive each posture against a deadline-forced
  AUTH_EXEC. NOT validatable on edr-dev (same ESF redaction reason as 2.5). The undecided-event payload
  byte-shape is locked by the schema + AuthExecDeciderTests cover the verdict matrix; what edr-qa adds is
  observing the event actually emitted from the wire after a real-kernel deadline exceedance. See
  `proposal.md` scenarios 3 / 4 / 5.

## 5. Undecided event emission

- [x] 5.1 Add `ApplicationControlUndecidedPayload` struct in `extension/edr/extension/EventSerializer.swift`
  carrying `pid`, `path`, `verdict`, `reason`, `fileSizeBytes`, `policyID`, `policyVersion`.
- [x] 5.2 Add `emitUndecidedEvent(...)` helper in `ESFSubscriber.swift`, called by the `dispatchAuthDecision`
  switch under `.allowWithUndecidedAudit` and `.denyWithUndecidedAudit` cases.
- [x] 5.3 Extend `schema/events.json`: add `application_control_undecided` to the `event_type` enum and the
  `oneOf` payload union; define `application_control_undecided_payload` with `pid`, `path`, `verdict`
  (`allow` | `deny`), `reason` (`deadline` | `read_failed`), `file_size_bytes`, `policy_id`,
  `policy_version`.
- [ ] 5.4 Server-side ingestion: route the new event type into a graph-builder no-op + a future alert
  source. Out of scope for this change; tracked as a v0.1.x follow-up because the operator dashboard work
  has not started.
- [ ] 5.5 L5 (edr-qa) validation under a notarized pkg: confirm the event payload byte-shape on the wire
  matches the schema and the Swift encoder's output. NOT validatable on edr-dev (same ESF redaction
  reason). See `proposal.md` scenarios 3 and 4.

## 6. CDHASH doc-comment fix (#207)

- [x] 6.1 Rewrite the inline comment in `buildAuthTuple` and the standalone `isHardenedRuntime` doc to own
  the lazy-page-mapping rationale without crediting Santa; add the explicit "this diverges from Santa"
  note so a migrating Santa admin is not surprised.

## 7. Documentation

- [x] 7.1 Update `docs/operations.md`'s "Application control" section: replace the stale "Phase 1 deletes
  the legacy endpoints; the new REST surface lands in later phases" framing with the v0.1.0 reality.
  Document the two carve-outs, the three postures + their trade-offs, the v0.1.0 default of `fail-closed`,
  and the behaviour-change note for RC upgrades.

## 8. v0.1.x follow-up scope (intentionally NOT in this change)

- [ ] 8.1 `app_control_policies.deadline_fallback` DB column + bootstrap migration.
- [ ] 8.2 REST surface (`PATCH /api/v1/app-control/policies/:id`) to set the per-policy posture; validator
  hook to `IsValidFallbackPosture`.
- [ ] 8.3 UI control + audit-row entry on posture change.
- [ ] 8.4 Server-side `application_control_undecided` event router: graph-builder no-op + alert source so
  the operator dashboard can chart the cold-cache rate over time.
- [ ] 8.5 SonarCloud / golangci-lint sweep for the new field (no new findings expected; the field is a
  simple string enum).
