# NE upgrade reboot signal: tasks

## 1. Agent: distinguish stale-after-upgrade from not-approved

- [x] `agent/receiver/upgradeprobe.go`: pure `parseNEUpgradePending(systemextensionsctlOutput, bundleID string) bool` (matches a line carrying the NE bundle id AND `waiting to uninstall on reboot`) + a thin `NEUpgradePending(ctx)` that runs `systemextensionsctl list` and feeds the parser. The exec wrapper is untested; the parser is table-tested.
- [x] `agent/receiver/loop.go`: track consecutive connect failures; add an optional `UpgradeProbe func() bool` hook + `staleProbeAfterFailures` gate. On a connect failure past the gate with the probe true, log the distinct WARN once per stale episode; otherwise keep the bare `receiver connect` WARN. Reset on a successful connect.
- [x] `agent/cmd/fleet-edr-agent/main.go`: wire `NEUpgradePending` as the NE loop's `UpgradeProbe` only (the ES loop is unchanged).

## 2. Host app: reboot-required signal

- [x] `extension/edr/edr/ExtensionManagerLogic.swift`: pure `rebootRequiredMessage(for:verdict:) -> String?` (non-nil only for activate + `.rebootRequired`).
- [x] `extension/edr/edr/main.swift`: in `finalizeAggregate`, emit the distinct operator-facing log line when `rebootRequiredMessage` is non-nil.
- [ ] (follow-up) GUI `UNUserNotificationCenter` popup, gated on host-app lifecycle + notification authorization.

## 3. Spec

- [x] `agent-xpc-receiver` delta: ADD "Distinct signal when a sysext upgrade leaves the NE registration stale".
- [x] `host-app-extension-manager` delta: ADD "A staged upgrade surfaces a reboot-required signal".

## 4. Tests

- [x] `agent/receiver/upgradeprobe_test.go`: table-driven parser tests (pending vs not-pending vs not-approved-no-old-version sample outputs).
- [x] `agent/receiver/loop_test.go`: bare WARN when no probe / probe false / under the failure gate; distinct WARN once when probe true past the gate; reset after a successful connect.
- [x] `extension/edr/Tests/EDRExtensionLogicTests/`: `rebootRequiredMessage` returns the message for activate+`.rebootRequired`, nil otherwise (fresh-install `.allSucceeded`, deactivate, failure).

## 5. Verification

- [x] `go test ./agent/...` + `task lint:go` + `spectrace --strict` + `openspec validate ne-upgrade-reboot-signal --strict`.
- [x] `swift test` for the host-app logic package.
- [ ] (gated on a release build) edr-qa signed-pkg upgrade: install vN, confirm NE telemetry, upgrade to vN+1, confirm the host-app log line + the agent distinct WARN fire and a fresh install does NOT prompt; reboot restores NE telemetry. Add "NE receiver reconnects after a sysext upgrade" to the edr-qa upgrade checklist.
