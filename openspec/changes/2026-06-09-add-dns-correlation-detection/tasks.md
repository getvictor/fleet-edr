# DNS-correlated C2 beacon detection — tasks

## 0. Spike (done, 2026-06-09)

- [x] Enable the DNS proxy on edr-qa via `edr enable-dns-proxy`; confirm no approval prompt is required on an already-approved host.
- [x] Confirm `dns_query` events flow end-to-end with the full payload (query_name/type/response_addresses/pid/path/uid) and the query→response follow-on pair.
- [x] Confirm the content filter and DNS proxy coexist (network_connect + dns_query + exec all flow in one session).

## 1. Engine interface

- [ ] Add `GetNetworkEventsForProcess(ctx, hostID string, pid int, tr TimeRange) ([]Event, error)` to the `GraphReader` interface (`server/detection/api/service.go`). The concrete `*mysql.Store` already implements it; this is interface plumbing.
- [ ] Add the method to the rules test kit's `GraphReader` fake / scenario store so catalog tests can exercise correlation without MySQL specifics.
- [ ] Unit-test the test-kit fake returns a process's `dns_query` + `network_connect` events within the time range, ordered by timestamp.

## 2. The rule

- [ ] `server/rules/internal/catalog/dns_c2_beacon.go`: `ID()`, `Techniques()` (`T1071.004`, conditionally `T1568.002`), `Doc()`, `Evaluate()`.
- [ ] Trigger reverse-direction on `network_connect`; join to a `dns_query` whose `response_addresses` contains the connection's `remote_address` for the same pid within the window.
- [ ] Suspicion gate per design.md (option C: suspicious process context AND the join; domain-entropy signal boosts severity + adds `T1568.002`).
- [ ] Emit one `High`/`Critical` finding citing the `exec`, `dns_query`, and `network_connect` event IDs; dedup by `ProcessID`.
- [ ] Register `dns_c2_beacon` in the catalog registry.

## 3. Tests + traceability

- [ ] Per-package table-driven unit test + `fixtures/dns_c2_beacon/` (positive: temp-exec → resolve high-entropy domain → connect to resolved IP; negatives: browser resolve+connect to a normal domain; suspicious process that resolves but connects elsewhere).
- [ ] Efficacy corpus `test/efficacy/corpus/T1071.004-dns-c2-beacon/` (`scenario.yaml` + `expected.yaml`). `attack.sh` deferred unless VM coverage is wanted.
- [ ] Add the spectrace `// spec:` marker on the rule test referencing the new `server-detection-rules-engine` scenario ID.
- [ ] `go test ./server/...`; `cd tools/spectrace && go run . check`; `openspec validate 2026-06-09-add-dns-correlation-detection --strict`.

## 4. DNS proxy on by default

- [ ] `edr/main.swift`: the `activate` flow enables the DNS proxy after the content filter (reuse `enableDNSProxy()`), so a freshly activated host has all three streams on. `enable-dns-proxy` / `disable-dns-proxy` remain for independent toggling.
- [ ] Update / add host-app extension-manager logic tests so `activate` asserts both the filter and the DNS proxy are enabled on success.
- [ ] Verify on edr-qa: a clean `edr activate` leaves the content filter AND the DNS proxy enabled.

## 5. Spec

- [ ] `server-detection-rules-engine` delta: MODIFY "Registered rule catalog" to include `dns_c2_beacon`; ADD "Requirement: DNS-correlated C2 beacon detection" with the positive + two negative scenarios.
- [ ] `host-app-extension-manager` delta: MODIFY the `activate` requirement so it enables the DNS proxy in addition to the content filter.

## 6. Docs + demo

- [ ] README: add DNS as the third telemetry stream, note it's the newest component (encrypted-DNS + failure modes are roadmap).
- [ ] Demo: recapture the demo dataset on edr-qa with DNS live; weave a `dns_c2_beacon` detection into one host's story as a 4th in-context attack (ties into the demo-data plan at `ai/demo/rich-demo-data-plan.md`).

## Deferred (separate changes)

- [ ] Default-on DNS activation in `activate` (after fail-open hardening).
- [ ] DNS-proxy `.mobileconfig` for unattended/MDM pre-approval.
- [ ] Fail-open proxy hardening (timeouts so a proxy fault can't break host DNS).
- [ ] Encrypted DNS (DoH/DoT), domain reputation, trained DGA model, NXDOMAIN/beacon-cadence signals.
