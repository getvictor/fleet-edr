# 0002. MVP ships macOS on Apple Silicon only

- Status: Accepted
- Date: 2026-04-18
- Deciders: getvictor

## Context

Choosing supported platforms early has out-sized downstream cost because
every later platform inherits a QA matrix, a signing pipeline, and a
telemetry-source abstraction burden. The forces at play:

- The agent's deepest telemetry source is Apple's Endpoint Security Framework
  (ESF), which only exists on macOS 11+. The richest detection surface
  requires entitlements that are only granted to system extensions, which in
  turn require notarisation + MDM-delivered profiles for production.
- Apple's final Intel Mac shipped in November 2023. The last macOS release
  that supports Intel hardware is Tahoe (macOS 26); every macOS release after
  Tahoe is Apple-Silicon-only. Pilot customers are overwhelmingly on Apple
  Silicon already.
- Linux and Windows need completely different telemetry stacks (eBPF +
  `tracee` / `falco-libs` for Linux, ETW + WDM for Windows). Each is a
  multi-quarter investment and deserves a separate ADR when that time
  comes. Shipping them prematurely bakes a shallow cross-platform story into
  the event envelope + process-graph model that we'd have to unwind later.
- Adding Intel Mac support means a second Apple signing + notarisation
  pipeline (`x86_64` lipo + signing + notarising) for a shrinking user base.

## Decision

MVP targets macOS 13+ on Apple Silicon only. Intel Macs are a deliberate
non-decision (will not do). Linux and Windows agents are deferred until
after the MVP pilot closes, and will each get their own ADR.

## Consequences

**Good:**

- One signing + notarisation pipeline, one QA VM, one architecture to
  optimise the Go + Swift build for.
- ESF APIs can be used at their most recent stable surface without
  back-porting concerns.
- The event envelope in `schema/events.json` can speak ESF vocabulary
  directly for MVP, with the explicit understanding that the envelope will be
  audited before a Linux or Windows agent ships (see
  `docs/best-practices.md` #2 "Platform-agnostic event envelope").

**Bad:**

- No cross-platform story for prospective customers with mixed fleets. The
  product pitch narrows to "Mac-heavy shops" until Linux / Windows land.
- The event envelope, process-graph model, and detection-rule API will need
  a non-trivial audit before the second platform lands. Doing this later
  rather than upfront is the explicit trade.
- No Intel Mac support means Intel-only fleets cannot pilot at all. This
  eliminates a tail of prospective customers; accepted because the tail is
  shrinking fast on its own.

## Alternatives considered

**macOS universal (arm64 + x86_64) from day one.** Rejected: doubles the
signing pipeline, expands the QA matrix, and targets a Mac population that
Apple itself has stopped shipping. Reconsider when a paying customer brings
an Intel fleet.

**Cross-platform from MVP.** Rejected: the ESF / eBPF / ETW telemetry
surfaces are too different to unify in a hurry, and a shallow
least-common-denominator event schema would constrain the Mac agent's
detection capabilities to whatever Windows and Linux can also produce. Wrong
order of operations.

**macOS kext instead of system extension.** Rejected: Apple has deprecated
kexts for new third-party development; system extensions are the supported
path. Revisiting this would be paddling upstream against Apple's platform
direction.

## References

- `docs/best-practices.md` section 2 (Cross-platform reach) captures the
  partial-adoption state.
- Apple [deprecation of kernel extensions](https://developer.apple.com/support/kernel-extensions/).
