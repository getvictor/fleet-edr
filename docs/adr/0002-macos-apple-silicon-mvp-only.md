# 0002. MVP ships macOS on Apple Silicon only

- Status: Accepted (amended 2026-06-14 and 2026-10-10; see Amendments below)
- Date: 2026-04-18
- Deciders: getvictor

## Context

Choosing supported platforms early has out-sized downstream cost because every later platform inherits a QA matrix, a signing pipeline, and a telemetry-source abstraction burden. The forces at play:

- The agent's deepest telemetry source is Apple's Endpoint Security Framework (ESF), which only exists on macOS 11+. The richest detection surface requires entitlements that are only granted to system extensions, which in turn require notarisation + MDM-delivered profiles for production.
- Apple's final Intel Mac shipped in November 2023. The last macOS release that supports Intel hardware is Tahoe (macOS 26); every macOS release after Tahoe is Apple-Silicon-only. Pilot customers are overwhelmingly on Apple Silicon already.
- Linux and Windows need completely different telemetry stacks (eBPF + `tracee` / `falco-libs` for Linux, ETW + WDM for Windows). Each is a multi-quarter investment and deserves a separate ADR when that time comes. Shipping them prematurely bakes a shallow cross-platform story into the event envelope + process-graph model that we'd have to unwind later.
- Adding Intel Mac support means a second Apple signing + notarisation pipeline (`x86_64` lipo + signing + notarising) for a shrinking user base.

## Decision

MVP targets macOS 13+ on Apple Silicon only. Intel Macs are a deliberate non-decision (will not do). Linux and Windows agents are deferred until after the MVP pilot closes, and will each get their own ADR.

## Amendment (2026-06-14): supported floor is macOS 26+

As of the v0.2.0 release the supported and tested floor for the agent is macOS 26+ (Tahoe), which is what QA validates against today. This is a support and test-coverage statement, not a code change: the codebase still builds for and installs on macOS 13+ (`extension/edr/Package.swift` declares `.macOS(.v13)` and `packaging/pkg/distribution.xml` allows `min="13.0"`), so the macOS-13 references in ADR-0007, ADR-0008, and the build tooling remain accurate descriptions of the technical floor. macOS 13, 14, and 15 (Ventura, Sonoma, Sequoia) may run but are untested and unsupported (there is no macOS 16 through 25: Apple jumped to year-based versioning at Tahoe / macOS 26). Revisit to either extend QA coverage down to 13 or raise the installer minimum to 26 (which would refuse older systems outright) once that posture is decided.

## Amendment (2026-10-10): the installer refuses anything older than macOS 26

The 2026-06-14 amendment stopped short of making the floor technical, and the two halves drifted: the app and both extensions were built with `MACOSX_DEPLOYMENT_TARGET = 26.2` while the installer still accepted macOS 13. A Mac on 13 through 26.1 installed the package and then could not launch what it installed.

The floor is now macOS 26.0 everywhere it is enforced:

- `MACOSX_DEPLOYMENT_TARGET = 26.0` in `extension/edr/edr.xcodeproj` for the app and both extensions. They compile at 26.0 with no availability errors, so nothing they call needs 26.1 or later.
- `packaging/pkg/distribution.xml` allows `min="26.0"` and its `volumeCheck()` refuses any major version below 26 with a message naming the requirement.
- `test/arch/macos_floor_test.go` fails the build if the installer minimum and the deployment target disagree.

`extension/edr/Package.swift` still declares `.macOS(.v13)`. That package is the SwiftPM facade the unit tests build, never a shipped artifact, and raising it needs a newer `swift-tools-version`. The macOS-13 references in ADR-0007 and ADR-0008 describe when those APIs appeared, which stays true.

Macs that are not on macOS 26 are refused at install time and must upgrade first. Supporting an older release again means lowering both numbers together and adding the `#available` guards the build would then demand.

## Consequences

**Good:**

- One signing + notarisation pipeline, one QA VM, one architecture to optimise the Go + Swift build for.
- ESF APIs can be used at their most recent stable surface without back-porting concerns.
- The event envelope in `schema/events.json` can speak ESF vocabulary directly for MVP, with the explicit understanding that the envelope will be audited before a Linux or Windows agent ships (see [`best-practices.md`](../best-practices.md) #2 "Platform-agnostic event envelope").

**Bad:**

- No cross-platform story for prospective customers with mixed fleets. The product pitch narrows to "Mac-heavy shops" until Linux / Windows land.
- The event envelope, process-graph model, and detection-rule API will need a non-trivial audit before the second platform lands. Doing this later rather than upfront is the explicit trade.
- No Intel Mac support means Intel-only fleets cannot pilot at all. This eliminates a tail of prospective customers; accepted because the tail is shrinking fast on its own.

## Alternatives considered

**macOS universal (arm64 + x86_64) from day one.** Rejected: doubles the signing pipeline, expands the QA matrix, and targets a Mac population that Apple itself has stopped shipping. Reconsider when a paying customer brings an Intel fleet.

**Cross-platform from MVP.** Rejected: the ESF / eBPF / ETW telemetry surfaces are too different to unify in a hurry, and a shallow least-common-denominator event schema would constrain the Mac agent's detection capabilities to whatever Windows and Linux can also produce. Wrong order of operations.

**macOS kext instead of system extension.** Rejected: Apple has deprecated kexts for new third-party development; system extensions are the supported path. Revisiting this would be paddling upstream against Apple's platform direction.

## References

- [`best-practices.md`](../best-practices.md) section 2 (Cross-platform reach) captures the partial-adoption state.
- Apple [deprecation of kernel extensions](https://developer.apple.com/support/kernel-extensions/).
