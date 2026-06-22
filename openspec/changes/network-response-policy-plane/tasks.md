# Tasks

## Extension (VM-gated)

- [ ] `extension/edr/networkextension/DNSProxyProvider.swift`: on-device `BlockDecision(query) -> {forward, denyLocal(answer)}` consulted before forwarding, defaulting to `forward` when no policy is loaded.
- [ ] Local denial for a matched block: synthesize an `NXDOMAIN` (or configured sinkhole answer) with no upstream contact, and emit block telemetry.
- [ ] Host containment ruleset: a declarative `NEFilterSettings` content-filter ruleset, persisted on device and re-applied on extension start (mirror the application-control snapshot persist/restore), with a management-lifeline allowance for the EDR server endpoint that resolves regardless of DNS-proxy health.
- [ ] Extension unit tests for the parts that are unit-testable (block-decision defaulting, ruleset persist/restore); live VM validation for the NetworkExtension-only paths.

## Host app

- [ ] `extension/edr/edr/main.swift`: wrap the `loadFromPreferences` / `saveToPreferences` flow in `enable-dns-proxy` / `disable-dns-proxy` with a timeout; on timeout exit non-zero with an actionable message instead of blocking.
- [ ] `extension/edr/edr/ExtensionManagerLogic.swift`: pure helper for the timeout/outcome decision so it is unit-testable.
- [ ] `extension/edr/Tests/EDRExtensionLogicTests/HostAppExtensionManagerTests.swift`: success path reports success and exits zero; timeout path exits non-zero with an actionable message.

## Server

- [ ] Network-response policy plane: blocklist + containment authoring, snapshot wire format, distribution, UI.

## Spec deltas

- [x] `extension-network-response` delta: ADDED default-forward, local-block-without-upstream, declarative containment.
- [x] `host-app-extension-manager` delta: ADDED bounded DNS proxy toggle subcommands.
