# DNS proxy on by default: tasks

## 1. Activate enables the DNS proxy

- [ ] `extension/edr/edr/main.swift`: the `activate` flow enables the DNS proxy after the content filter. Note:
  `enableContentFilter()` and `enableDNSProxy()` each call `exit()` in their completion handlers today, so they must be
  refactored to chain via a completion callback (enable filter, then on success enable DNS proxy, then exit) rather than
  exiting from each handler.
- [ ] `enable-dns-proxy` / `disable-dns-proxy` remain for independent toggling (unchanged).

## 2. Tests + verification

- [ ] Host-app extension-manager logic tests assert `activate` enables both the content filter and the DNS proxy on
  success.
- [ ] Verify on edr-qa: a clean `edr activate` leaves the content filter AND the DNS proxy enabled.

## 3. Spec

- [ ] `host-app-extension-manager` delta: MODIFY the `activate` requirement so it enables the DNS proxy in addition to
  the content filter.

## Deferred (separate changes)

- [ ] Fail-open proxy hardening (timeouts so a proxy fault can't break host DNS); higher priority now that `activate`
  enables the proxy by default.
- [ ] DNS-proxy `.mobileconfig` for unattended/MDM pre-approval.
