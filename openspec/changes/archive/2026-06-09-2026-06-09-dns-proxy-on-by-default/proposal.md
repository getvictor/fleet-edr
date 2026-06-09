# DNS proxy on by default

## Why

DNS is the EDR's third telemetry stream, and the differentiator is correlating exec + network + DNS. The capture and
the `dns_c2_beacon` correlation rule already ship, but the DNS proxy is opt-in (`enable-dns-proxy`), so a freshly
activated host produces only two of the three streams until an operator turns DNS on. For the product to lead with
three-stream correlation, a host should emit all three streams the moment it is activated.

This change enables the DNS proxy by default in the host app's `activate` flow, alongside the content filter, so the
DNS stream (and the detections that depend on it) are on out of the box. The proxy stays independently toggleable.
Because the proxy now sits in every activated host's DNS data path, fail-open hardening (a proxy fault must not break
host DNS) becomes a near-term follow-up.

## What Changes

- The host app's `activate` flow enables the DNS proxy after the content filter on success. `enableContentFilter()` and
  `enableDNSProxy()` in `extension/edr/edr/main.swift` each call `exit()` in their completion handlers today, so they
  are refactored to chain via a completion callback (enable the filter, then on success enable the DNS proxy, then
  exit) rather than exiting from each handler. `enable-dns-proxy` / `disable-dns-proxy` remain for independent toggling.
- Host-app extension-manager logic tests assert that `activate` enables both the content filter and the DNS proxy on
  success.
- Verified on the QA VM: a clean `edr activate` leaves the content filter AND the DNS proxy enabled.

### Not in this change (deferred)

- Fail-open proxy hardening (timeouts so a proxy fault can't break host DNS): its own follow-up, higher priority now
  that `activate` enables the proxy by default.
- A DNS-proxy `.mobileconfig` for unattended/MDM pre-approval: the proxy enables without it on an approved host.
