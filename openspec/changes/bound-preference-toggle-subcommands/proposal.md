# Bound the host-app preference-toggle subcommands

## Why

`enable-dns-proxy`, `disable-dns-proxy`, `enable-filter` and `disable-filter` each call `loadFromPreferences`, then `saveToPreferences`, then sit in `dispatchMain()`. Nothing bounds either call. If a completion handler is never invoked, the subcommand waits forever with no output.

Issue #905 recorded this as a hang reproducible over SSH. That claim was wrong, and measuring it is what corrected the design. On edr-dev (macOS 26.3), over SSH with no console session, against an already-approved configuration:

| Subcommand | Result | Wall clock |
| --- | --- | --- |
| `disable-dns-proxy` | `DNS proxy disabled`, exit 0 | under 1s |
| `enable-dns-proxy` | `DNS proxy enabled successfully`, exit 0 | under 1s |

So the wait is unbounded but does not routinely hang, and the severity claim in #905 was overstated. What the measurement also surfaced is the thing that matters more: saving a configuration the machine has not yet approved raises a console consent prompt and does not return until a human answers it. A bound chosen to "fail fast", which is how #905 and the archived requirement both framed it, would abort that approval and break the documented `launchctl asuser` enable flow.

This change therefore ships the bound the archived `2026-06-22-resilient-network-enforcement` change specified, sized against the consent prompt rather than against a hang: 120 seconds, long enough to read a prompt and click Allow, short enough that an unattended invocation reports something instead of blocking forever.

## What changes

- `PreferencesLatch`, `defaultPreferencesTimeout` and `preferencesTimeoutMessage` in `ExtensionManagerLogic.swift`, which is compiled by both the Xcode target and the SwiftPM logic library, so the behaviour is unit-testable. `main.swift` carries top-level executable code and cannot be.
- `main.swift` arms a watchdog on each of the four toggle subcommands and routes their terminal paths through `finishToggle`.

`finishToggle` returns `Never`, so replacing an `exit` call with it cannot introduce a fall-through. That was the one hazard here: `exit` is `Never` and the code after it is unreachable, while a `Void`-returning replacement would have silently fallen through into the success path on every error branch.

The bound covers all four toggles rather than only the two the archived requirement named. The four call sites are identical, and a helper guarding half of them would leave the same defect under a different subcommand.

`activate` is deliberately left unbounded: its flow includes waiting for a human to approve a system-extension installation.

## Impact

- Affected specs: `host-app-extension-manager`
- Affected code: `extension/edr/edr/main.swift`, `extension/edr/edr/ExtensionManagerLogic.swift`, `extension/edr/Tests/EDRExtensionLogicTests/PreferenceToggleBoundTests.swift`
- Operator-visible: a toggle whose preferences round-trip stalls now exits non-zero after 120 seconds with guidance, instead of waiting without limit. No change to any round-trip that completes, which is every one measured on edr-dev.
