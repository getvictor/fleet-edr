# Re-sync application control after a server policy-version regression: tasks

## 1. Server wire field

- [ ] `server/rules/api/types.go`: add `PolicyEpoch int64 \`json:"policy_epoch"\`` to `SetApplicationControlPayload`. In `MarshalSetApplicationControlPayload`, set it to `p.UpdatedAt.UnixMicro()` when `UpdatedAt` is non-zero, else `0` (keeps the zero-`UpdatedAt` test/legacy path emitting `policy_epoch:0`, the "unknown epoch" sentinel).
- [ ] Confirm `buildSnapshotPayload` (`server/rules/internal/appcontrol/service.go`) already re-reads the policy after the version bump, so `UpdatedAt` is the post-mutation timestamp at fan-out time. No change needed there.

## 2. Schema

- [ ] `schema/events.json`: add `application_control_resync` to the `event_type` enum, add its payload to the envelope `oneOf`, and define `application_control_resync_payload` (`policy_id`, `previous_version`, `new_version`, `previous_epoch`, `new_epoch`, `reason`).

## 3. Extension gate + event

- [ ] `extension/edr/extension/ApplicationControlStore.swift`: add `policyEpoch` to `ApplicationControlSnapshot` (and `.empty = 0`); add optional `policyEpoch` (`policy_epoch`) to `ApplicationControlDocument`; carry it through `makeSnapshot` (nil -> 0). Replace the version-only gate with "accept iff version advanced OR epoch advanced (same policy)"; capture the prior version/epoch under the lock; on a version-regression-with-epoch-advance accept, log at `error` and call a `resyncReporter` closure.
- [ ] `extension/edr/extension/EventSerializer.swift`: add `ApplicationControlResyncPayload`.
- [ ] `extension/edr/extension/main.swift`: wire `ApplicationControlStore.shared.resyncReporter` to `serializer.serialize(eventType: "application_control_resync", payload:)` -> `server.send`.

## 4. Tests

- [ ] `server/rules/api/app_control_wire_test.go`: pin `policy_epoch` in the JSON-keys test; add a `policy_epoch`-from-`UpdatedAt` test (real timestamp -> UnixMicro, zero -> 0); extend the PBT to draw an `UpdatedAt` and assert the epoch round-trips.
- [ ] `extension/edr/Tests/EDRExtensionLogicTests/ApplicationControlStoreTests.swift`: add the epoch param to the `document()` helper; add tests: (a) version regression with epoch advance is accepted and re-syncs the ruleset; (b) older-on-both-axes is rejected; (c) epoch-0 (legacy) snapshot still gated by version; (d) the resync reporter fires with the right previous/new values on the regression path and does NOT fire on a normal forward apply.
- [ ] `test/integration/app_control_block_test.go` (or a sibling): assert that a server policy-version regression (simulating a DB restore: bump `updated_at` forward while `version` is lower) produces a fan-out payload whose `policy_epoch` advanced, so the host would re-sync rather than freeze.

## 5. Spec

- [ ] `extension-application-control` delta: MODIFY "Snapshot is the source of truth for decisions" (epoch+version acceptance, redefine stale), ADD a restore-resync scenario, ADD the "Application control re-sync event" requirement.
- [ ] `server-application-control` delta: MODIFY "Command fan-out on policy mutation" so the payload carries `policy_epoch`.

## 6. Verification

- [ ] `go test` (wide `-coverpkg`) green on `server/rules/...` and `test/integration/...`.
- [ ] `swift test` green on the extension logic tests.
- [ ] `task lint:go`, `task lint:dashes`, `task lint:md`; `openspec validate fix-app-control-version-regression-resync --strict`; spectrace; events.json well-formed.
- [ ] Manual QA on a VM against dev:server (OTLP -> SigNoz): reproduce the freeze, confirm the epoch path re-syncs enforcement and the `application_control_resync` event lands.
