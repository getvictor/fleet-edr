# Report activation outcomes to the operator: tasks

## 1. Fix

- [x] `extension/edr/edr/main.swift`: a `Report` helper that writes operator-facing lines to stdout or stderr AND mirrors them to the unified log with an explicit public privacy annotation. Every extension-request outcome now goes through it, where previously the whole delegate reported only to a log that redacted the reason.
- [x] `extension/edr/edr/ExtensionManagerLogic.swift`: `reportStream(for:)`, the pure decision of which stream an outcome belongs on. Split out for the same reason `postAggregateStep` is: `main.swift` carries top-level executable code and is excluded from the SwiftPM logic module, so anything living only there cannot be unit tested.
- [x] The enable and disable paths' error output moved from stdout to stderr through the same helper, so the command's error reporting is coherent rather than split by which half of it failed.

## 2. Spec

- [x] `host-app-extension-manager` delta: ADDED "Activation outcomes are reported to the operator".

## 3. Tests

- [x] `HostAppExtensionManagerTests.swift`: failure routes to the error stream, successful outcomes to standard output, and every outcome the aggregator can record routes somewhere. The last one is the property that actually pins the defect: it was silence, so total coverage is what prevents a new outcome from being reported nowhere.

## 4. Verification

- [x] `xcodebuild` Debug build green; `swift test` 227 tests; `swiftlint --strict`.
- [x] Behaviour verified by running the built binary directly. `edr disable-filter` against a host where the save fails now puts `Disabling content filter...` on stdout and `ERROR: Failed to disable filter: permission denied` on stderr, where before both went to stdout and an activation failure produced nothing at all on either stream.

## 5. Not covered

- [ ] Not verified on edr-dev. That VM's app bundle is in the broken state this issue was found through: repeated bundle replacement left an invalid signature, the kernel logs an AMFI complaint for `com.fleetdm.edr`, and a byte-identical binary placed at the app's executable path still produces the OLD log output, so the host is not executing what is deployed to it. The fix is verified on a working machine instead; edr-dev needs rebuilding before it can validate host-app changes again.
