# Network-response enforcement policy plane

## Why

The DNS-proxy resilience change (`resilient-network-enforcement`, #471) shipped the incident fix (bounded forward deadline, fail-open close) and the health watchdog with policy-aware bypass. Its delta also declared the requirements for the on-device enforcement decision surface (default-forward, local block-denial) and declarative host containment, plus a bounded host-app DNS-proxy toggle. Those parts were explicitly deferred in that change (its Section 3, Section 4, and Section 7 "follow-ups, tracked separately") and were never implemented: there is no `BlockDecision` seam, no local-denial / sinkhole path, no containment ruleset persistence, and the `enable-dns-proxy` / `disable-dns-proxy` subcommands still block on the preferences round-trip with no timeout.

Carrying those requirements in the canonical spec ahead of the code made the spec claim behavior the product does not have. This change holds the deferred requirements as an in-flight proposal until the policy plane (blocklist + containment authoring, snapshot wire format, distribution, UI) and the bounded toggle land, so the canonical spec reflects only shipped behavior in the meantime.

## What changes

- Re-declare the deferred network-response requirements as a pending change (no behavior change yet):
  - `extension-network-response`: default network action is forward (deny only on explicit match); a blocked DNS query is answered locally without upstream; host network containment is declarative and survives a provider restart.
  - `host-app-extension-manager`: the DNS proxy toggle subcommands fail fast instead of hanging.
- Implement the on-device decision seam, local denial, containment ruleset persistence, and the bounded toggle, with the server-side policy plane that feeds them. The macOS NetworkExtension paths are VM-gated.

These requirements were trimmed out of the canonical spec when `resilient-network-enforcement` was archived for the 0.3.0 release, because their implementation was not complete.
