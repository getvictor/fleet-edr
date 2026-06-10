# 0007. XPC peer validation uses libxpc-side code-signing requirement; no audit_token layer

- Status: Accepted
- Date: 2026-05-25
- Deciders: getvictor

## Context

The system extension and the network extension each vend a Mach service that the userland Go agent connects to. That XPC channel is the trust boundary between Apple-mediated kernel-side capture (ESF + NEFilter entitlements) and the agent's enrollment / queueing / upload code: anything that completes the connection accept gets the event firehose AND the ability to mutate the active application-control blocklist via `application_control.update` messages. The bar for "is this peer actually the agent?" therefore has to be high enough that an unrelated process on the device cannot connect, drain telemetry, or push a malicious blocklist.

macOS exposes two generations of API for verifying the code-signing identity of an XPC peer, and the project has to commit to one as its authoritative peer-validation gate:

1. **Legacy (pre-macOS 13).** User code extracts the audit token from the connection (`xpc_connection_get_audit_token`), passes it to `SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit` to obtain a `SecCode` handle, builds a `SecRequirement` from a requirement-language string via `SecRequirementCreateWithString`, and calls `SecCodeCheckValidity` to verify the peer. The validation lives entirely in user code; the framework gives you the audit token, you do the rest.

2. **Modern (macOS 13+).** User code calls `xpc_connection_set_peer_code_signing_requirement(connection, requirementString)` once at accept time. libxpc itself reads the audit token, resolves the `SecCode`, evaluates the requirement, and cancels the connection on failure. No event handler ever runs for a peer that fails the check.

Reality on the ground in this codebase, before this ADR is written:

- `extension/edr/extension/XPCServer.swift` line 187 calls `xpc_connection_set_peer_code_signing_requirement(event, peerCodeSigningRequirement)` inside `handleListenerEvent`, before the `xpc_connection_set_event_handler` registration. The requirement string is the production string (Apple anchor + the FDM team ID `FDG8Q7N4CC`) in release builds, OR the production string OR a pinned ad-hoc cdhash in `#if DEBUG` builds for SIP-disabled dev VMs.
- There is no `audit_token_t`-based fallback validation in user code. There is no `SecCodeCheckValidity` call anywhere in the extension target.
- The project targets macOS 13+ exclusively (`extension/edr/Package.swift` declares `platforms: [.macOS(.v13)]`; ADR-0002 commits the MVP to Apple Silicon + macOS 13+).
- The `extension-xpc-server` spec requires "the extensions SHALL reject any inbound XPC connection whose peer does not satisfy a code-signing requirement chained to the Apple anchor and the Fleet Device Management team identifier" (`openspec/specs/extension-xpc-server/spec.md`). The spec is agnostic about which API enforces that requirement, which is what this ADR pins down.

The question this ADR settles: should the extension keep using only the libxpc-side gate, or should it also call `SecCodeCheckValidity` against the same requirement string in user code (a "defense in depth" layering of the two APIs)? The question keeps coming back in AI code review (`coderabbitai[bot]` raised it on PR #269) and was historically answered "libxpc-only is enough" in conversation; writing it down stops the question being relitigated every cycle.

The forces:

- The two APIs consult the **same source of truth**. Both read the same audit token (kernel-supplied, not forgeable from user space), both resolve the same `SecCode`, both evaluate the same requirement language. Layering two calls that read the same kernel-backed evidence does not compound assurance; it doubles the surface area without raising the assurance ceiling.

- The libxpc-side gate runs **before any event handler is invoked**. The user-code `SecCodeCheckValidity` runs _inside_ the accept handler, which on macOS XPC means inbound messages from the peer can already be queued behind it. For a trust-boundary channel where the cost of a single mis-accepted message is the ability to push a malicious blocklist or drain telemetry, "rejected by the framework before any message reaches user code" is the strictly safer ordering.

- The macOS-13+ target is a hard requirement, not a soft one. ADR-0002 commits the MVP to macOS 13+. There is no scenario in the current roadmap where a peer-validation path that requires macOS 13 would not be acceptable.

- The codebase is small. Carrying a duplicate validation pipeline on a small team is paid in maintenance, not delivered as security. A second code path that has to be kept in sync with the first across every requirement-string change is real ongoing tax.

## Decision

Peer validation in the extension XPC servers uses `xpc_connection_set_peer_code_signing_requirement` as the sole gate. The system extension calls it from `handleListenerEvent` on every `XPC_TYPE_CONNECTION` event before registering the peer's event handler. The requirement string lives in `PeerCodeSigningRequirement.production` (release builds) or `PeerCodeSigningRequirement.debug` (debug builds; production clause OR a pinned ad-hoc cdhash).

The extension MUST NOT additionally call `SecCodeCheckValidity`, `SecCodeCopyGuestWithAttributes`, `SecRequirementCreateWithString`, or any other user-side variant of the same check against the same requirement string. Adding the legacy API alongside the modern API is explicitly rejected by this ADR; reviewers (human or AI) raising it should be pointed here.

If the threat model ever requires validation of an attribute the requirement DSL cannot express (e.g. per-connection per-bundle-id allow-list that varies at runtime, or auxiliary signature-info checks like notarization staple presence), that is a different decision the project will write a separate ADR for. This ADR pins only the choice between the two existing peer-validation APIs.

## Consequences

**Good:**

- Single point of enforcement. One call, one requirement string, one place to audit when the threat model evolves.

- Strictly stronger timing than the user-side variant. The framework cancels the connection before `set_event_handler` is invoked; no inbound peer message can race the validation.

- Apple-supported pattern. The API was introduced in macOS 13 as the recommended replacement for the user-side `audit_token` + `SecCode` flow. Any future libxpc hardening (additional signature-verification steps, certificate-pinning knobs, etc.) Apple lands lifts the extension for free.

- Smaller code surface. No `Security.framework` imports inside the extension's accept path. No requirement-string-construction helper to keep in sync with the libxpc-side string. No per-platform `#if available(macOS 13, *)` shim.

- Composable with future tightening. The requirement string is the single tunable; narrowing the gate (see "Deferred tightening" below) is a one-line edit to the `PeerCodeSigningRequirement` constants.

**Bad:**

- Locked into macOS 13+ for peer validation. Backporting the extension to macOS 12 or earlier would require switching to (or layering on) the `audit_token_t` flow. ADR-0002 already pins the MVP to macOS 13+, so this is not a near-term constraint, but it is a real entry on the "what would we have to redo to support an older floor" list.

- A bug in libxpc's requirement evaluator cannot be supplemented by user-code checks of the same requirement. The user-side variant would not actually help here (it reads the same audit token and consults the same `SecCode`), so this is more theoretical than practical, but it is a real surface that an attacker with a libxpc 0-day could exploit. The mitigation is staying current on macOS security updates, not adding the legacy API alongside.

- The validation gate is opaque on the user side: there is no per-connection trace of which clause of the requirement string matched. If a future debug exercise needs that, the path is to add a one-shot `SecCodeCheckValidity` _for diagnostic logging only_ under a debug guard, not to switch the authoritative gate.

## Deferred tightening

The production requirement currently accepts any binary chained to the Apple anchor and signed by the FDM team:

```text
anchor apple generic and certificate leaf[subject.OU] = "FDG8Q7N4CC"
```

This is the right gate against the realistic threat model (an arbitrary process on the device trying to connect). It is _not_ the tightest gate possible: the requirement DSL also supports pinning a specific signing identifier or designated requirement hash:

```text
(anchor apple generic and certificate leaf[subject.OU] = "FDG8Q7N4CC")
  and identifier "com.fleetdm.edr.agent"
```

Adding the `identifier` clause would constrain the gate to one specific FDM-signed binary, raising the bar from "any FDM-signed binary" to "specifically the EDR agent binary." This is a strict narrowing that aligns with how top-end EDRs scope their IPC acceptance.

The reason it is **deferred** rather than landed here:

- It changes the operational contract. Once the identifier is pinned, renaming the agent's signing identifier (binary rename, bundle-id shift on a future packaging change) breaks XPC accept until both the agent and the extension ship the new value together. That is a coordination cost the agent's release process is not yet wired to handle (no compatibility window, no warning on mismatch).
- It requires deciding which identifier to pin. Ad-hoc dev builds sign with the binary basename (`fleet-edr-agent`); production builds will eventually sign with a chosen signing identifier the release pipeline pins. Until the production identifier is fixed in `task package:agent` (or equivalent), pinning would pick a value that the eventual release contradicts.
- It is a tightening, not a fix. The current gate is correct against unauthorized processes; the deferred work raises the bar against a more sophisticated threat (a trusted-but-malicious insider with an FDM signing key for a different binary). That threat class is not in the MVP threat model.

When the agent's production signing-identifier story is locked down, narrow the constants in `PeerCodeSigningRequirement` to include the `identifier "..."` clause, update both the spec scenarios and the `XPCServerLogicTests.testProductionRequirementPinsTheFleetTeamID` assertion, and reference this ADR's "Deferred tightening" section from the change description.

## Alternatives considered

**Use both APIs (defense in depth).** Layer `xpc_connection_set_peer_code_signing_requirement` AND a manual `audit_token` + `SecCodeCheckValidity` check in `handleListenerEvent`, both against the same requirement string. Rejected because the two APIs consult identical evidence (same audit token, same `SecCode` resolution, same requirement language); a bug that bypasses one almost certainly bypasses the other. The duplication doubles the surface area (two code paths to keep in sync; two failure modes to log distinctly; one path or the other to be the "authoritative" verdict) without raising the assurance ceiling. The proposal often shows up framed as "more is more," but for peer validation it is "two locks keyed alike."

**Use only the legacy audit_token + SecCodeCheckValidity flow.** Implement validation entirely in user code, drop the libxpc-side call. Rejected because the user-side check has a TOCTOU window (messages can be queued behind the validation logic if the implementation isn't careful), the codebase would carry the full `Security.framework` interaction surface in the accept path, and the project is on macOS 13+ where the framework gate exists for exactly this reason.

**Pin the agent identifier in the requirement string now.** As discussed under "Deferred tightening", this is a strict improvement but ships before the production signing identifier is locked in the release pipeline. Landing it in two PRs (one for the extension, one for the agent release) without a compatibility window would break the XPC accept path for any agent rolling out during the transition. Deferred to a release-coordinated change.

**Wrap the requirement string in a more permissive pattern (anchor apple OR anchor apple generic).** Considered briefly because some internal FDM tools sign with developer-id (`anchor apple generic`) while others sign with Apple Distribution (`anchor apple`). Rejected because the EDR agent ships through the Developer ID notarization path; the `anchor apple generic` clause is correct for that path and the EDR agent only.

## References

- `extension/edr/extension/XPCServer.swift` lines 17-44 (the `PeerCodeSigningRequirement` enum + the active `peerCodeSigningRequirement` constant chosen via `#if DEBUG`).
- `extension/edr/extension/XPCServer.swift` line 187 (the single call site of `xpc_connection_set_peer_code_signing_requirement`).
- `extension/edr/Package.swift` (`platforms: [.macOS(.v13)]`).
- `openspec/specs/extension-xpc-server/spec.md` - Requirement "Peer code-signing validation" and the four scenarios that pin the contract from the spec side.
- `extension/edr/Tests/EDRExtensionLogicTests/XPCServerLogicTests.swift`
  - the four `peer-code-signing-validation/*` tests that assert the requirement strings include the Apple anchor + team ID and that the production string excludes the cdhash clause.
- ADR-0002 "macOS Apple Silicon MVP only" (the macOS 13+ target this ADR depends on).
- Apple Developer documentation: [`xpc_connection_set_peer_code_signing_requirement`](https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_code_signing_requirement) (the modern API this ADR picks).
- Apple Developer documentation: [Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html) (the DSL the requirement strings are written in).
