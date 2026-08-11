# Report activation outcomes to the operator: tasks

## 1. Fix

- [x] `extension/edr/edr/ExtensionManagerLogic.swift`: `Reporter`, the operator-facing output boundary. It writes each line to a stream sink AND mirrors the same text to a log sink, where previously the whole delegate reported only to a log that redacted the reason. The sinks are injected rather than called directly because that is what makes the boundary testable: the defect here was SILENCE, and a test that exercises only the routing rule passes whether or not the command ever speaks. `main.swift` carries top-level executable code and is excluded from the SwiftPM logic module, so a Reporter living there could not be tested at all. `reportStream(for:)` stays a separate pure decision so a caller can ask where an outcome belongs without producing output.
- [x] `extension/edr/edr/main.swift`: the production wiring only, one `Reporter` over real stdout, stderr and the unified log, with explicit public privacy annotations on the log interpolations. Every extension-request outcome goes through it, including the awaiting-approval state, which had no report at all despite being the state that most resembles a hang. Stderr goes through `write(contentsOf:)`, the macOS-10.15.4+ replacement for a `write(_:)` that traps rather than returning an error on a broken pipe; the file already used it on the usage path.
- [x] The enable and disable paths' error output moved from stdout to stderr through the same boundary, so the command's error reporting is coherent rather than split by which half of it failed.

## 2. Spec

- [x] `host-app-extension-manager` delta: ADDED "Activation outcomes are reported to the operator".

## 3. Tests

- [x] `HostAppExtensionManagerTests.swift`: a `Reporter` over recording sinks, asserting the failure text lands verbatim on the error stream and nothing lands on stdout, that the SAME text reaches the log (an os_log interpolation of a non-literal defaults to `privacy: .private`, which is how the original reason read back as `<private>`, so asserting the full string is what would catch a redacted reintroduction), that the approval message is reported and names where the approval happens, and that no outcome produces zero lines.
- [x] Mutation-checked rather than assumed, because the first version of these tests asserted only the routing rule and would have passed against the bug. Four mutations, each caught: dropping the stderr write, routing a failure to stdout, logging `<private>` in place of the message, and removing the approval report.

## 4. Verification

- [x] `xcodebuild` Debug build green; `swift test` 228 tests; `swiftlint --strict` 0 violations; `spectrace check --strict` 775/775; `openspec validate --strict`.
- [x] Behaviour verified by running the built binary directly. `edr disable-filter` against a host where the save fails now puts `Disabling content filter...` on stdout and `ERROR: Failed to disable filter: permission denied` on stderr, where before both went to stdout and an activation failure produced nothing at all on either stream.

## 5. Not covered

- [ ] Not verified on edr-dev. That VM's app bundle is in the broken state this issue was found through: repeated bundle replacement left an invalid signature, the kernel logs an AMFI complaint for `com.fleetdm.edr`, and a byte-identical binary placed at the app's executable path still produces the OLD log output, so the host is not executing what is deployed to it. The fix is verified on a working machine instead; edr-dev needs rebuilding before it can validate host-app changes again.
