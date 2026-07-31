# Keep the DNS proxy out of another resolver's dependency path: tasks

## 1. Claim decision

- [x] `extension/edr/networkextension/DNSForwardPolicy.swift`: new pure-Foundation type deciding how a claimed flow's forward is routed, from the source signing identifier plus an injected entitlement probe (same seam as `DNSProxyHealth`'s injected clock). Carves out our own signing identifier and keeps the probe lazy so the common path costs one string comparison. Also states which routings may feed the health watchdog.
- [x] `extension/edr/networkextension/NetworkExtensionProviderLookup.swift`: the SecCode half. Resolves the flow's audit token to a `SecCode`, reads `kSecCodeInfoEntitlementsDict`, and reports whether the process holds `com.apple.developer.networking.networkextension`. Memoised per `(pid, pidversion)` with a bounded cache, following `SigningInfoFallback`'s pattern. Fails open (false) when the source cannot be resolved.

## 2. Interface pinning

- [x] `extension/edr/networkextension/InterfaceSnapshot.swift`: name-keyed `NWInterface` view fed by an `NWPathMonitor`, plus the routing-to-`NWParameters` translation shared by the UDP and TCP forward paths (`requiredInterface` for ordinary flows, `prohibitedInterfaceTypes = [.other]` for tunnel-avoiding ones). Name matching is the bridge because `NEAppProxyFlow.networkInterface` vends an `nw_interface_t` and `NWParameters.requiredInterface` wants an `NWInterface`, with no initialiser between them.

## 3. Provider wiring

- [x] `extension/edr/networkextension/DNSProxyProvider.swift`: consult the forward policy in `handleNewFlow`; build the flow context once and thread it plus the `ForwardRoute` through the UDP and TCP paths; keep tunnel-avoiding outcomes out of `health.record`; note each routed-around provider once; correct BOTH copies of the stale "no infinite loop" comment (the class header and the one at the UDP forward site) and the bypass comment that claimed the watchdog fails open.

## 4. Spec

- [x] `extension-network-response` delta: ADDED "DNS proxy forwards away from another provider's tunnel" covering the entitlement rule, the own-provider carve-out, tunnel-avoiding egress, interface pinning for ordinary flows, the prohibition on declining, watchdog exclusion, and once-per-provider reporting.

## 5. Tests

- [x] `DNSForwardPolicyTests.swift`: tunnel-avoiding routing for a third-party provider, ordinary routing for an application, ordinary routing for our own identifier despite holding the entitlement, probe laziness, probe-decides-not-string, empty signing identifier, and which routings feed the watchdog. Scenario markers on the three spec-backed cases.
- [x] `InterfaceSnapshotTests.swift`: unknown name resolves nil, name lookup against live interfaces, update replaces the snapshot so a downed tunnel stops being pinned, ordinary routing carries the bound interface and leaves an unbound flow on default routing, tunnel-avoiding routing prohibits `.other` and ignores the bound interface, and the UDP/TCP builders use the right transport.

## 6. Verification

- [x] `swift test` (196 tests) and `xcodebuild` Debug build green.
- [x] Entitlement detection validated against live processes on a real host before wiring: WireGuard's NE reports `[packet-tunnel-provider]` (true), our own NE reports `[content-filter-provider-systemextension, dns-proxy-systemextension]` (true, hence the carve-out), and `mDNSResponder` reports 44 entitlements with no network-extension entry (false), confirming ordinary system DNS stays claimed.
- [x] `swiftlint lint --strict`; `openspec validate exclude-tunnel-resolver-flows --strict`; spectrace 777/777; dash + markdown lints.
- [x] Live macOS VM (edr-dev) against `task dev:server`. WireGuard could not be used: its macOS app is Mac App Store only, which needs an Apple ID sign-in, and the Homebrew `wireguard-tools` route has no network extension so it would not hold the entitlement. Instead a probe binary was ad-hoc signed WITH `com.apple.developer.networking.networkextension` (SIP is off on edr-dev, so SecCode reports arbitrary ad-hoc entitlements), standing in for a tunnel provider and exercising the real SecCode path inside the live extension.

  A first implementation DECLINED those flows, which is what the issue asks for. The VM proved that wrong and the design was reworked; the measurement is recorded in `DNSForwardPolicy`'s type comment. Declining, and separately a diagnostic build that declined every flow:

  | client                 | declined           | proxy configuration disabled |
  | ---------------------- | ------------------ | ---------------------------- |
  | `dig` (v4 and v6)      | no answer          | resolves                     |
  | Go probe               | connection refused | resolves                     |
  | `dscacheutil`          | 0 addresses        | resolves                     |
  | `ping` name resolution | fails              | resolves                     |

  With the shipped routing design instead, on the same host: the entitled probe and entitled `dig` resolve over both v4 and v6, ordinary clients are unchanged, each routed-around provider is logged exactly once (2 lines for 2 providers, not one per flow), and `dns_query` telemetry is emitted for BOTH classes (6 + 2 events for the two entitled binaries, alongside the ordinary ones) where declining had produced none.
