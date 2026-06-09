# DNS-correlated C2 beacon detection

## Why

The EDR's differentiation is three-layer composition plus correlation: it joins process (`exec`), network
(`network_connect`), and DNS (`dns_query`) telemetry that no single open-source tool joins today. Two of the three
streams already drive detection rules; DNS does not. Until a rule actually correlates a DNS query with the exec that
issued it and the network connection that followed, the three-stream claim is unproven in the product: the detection
catalog reads as "process plus network," which is what commodity agents already ship.

The on-device DNS capture is built and verified: `DNSProxyProvider` emits `dns_query` events (query name, type, resolved
addresses, originating pid/path) through the network extension, the server ingests and associates them to processes, and
a spike on a SIP-on host confirmed the proxy enables cleanly and all three streams flow and coexist. What is missing is
the detection layer: a rule that joins the three streams into a single, auditable finding.

This change adds `dns_c2_beacon`, a correlation rule that fires when a suspicious process resolves a domain and then
connects to the resolved address, citing the `exec`, `dns_query`, and `network_connect` events together. It makes the
three-stream correlation a spec'd, tested behavior a reviewer can confirm by reading the repo.

## What Changes

- Expose the existing network/DNS per-process query primitive on the detection rules-engine interface.
  `(*mysql.Store).GetNetworkEventsForProcess(hostID, pid, TimeRange)` already returns a process's `network_connect` and
  `dns_query` events; add it to the `GraphReader` interface (and the rules test kit's fake) so rules can reach DNS plus
  network events for correlation. No storage or query change.
- Add the `dns_c2_beacon` detection rule under `server/rules/internal/catalog/`, registered in the catalog so it
  evaluates against every batch. It triggers reverse-direction on a `network_connect` event, joins to the connecting
  process's `dns_query` events (matching a resolved address to the connection's remote address, on normalized IP
  values), gates on a suspicion signal to keep false positives near zero on benign browser traffic, and emits one
  `High` finding citing the `exec`, `dns_query`, and `network_connect` events. MITRE: `T1071.004` (Application Layer
  Protocol: DNS), and `T1568.002` (Domain Generation Algorithms) when the domain-entropy signal contributes.
- Ship the rule's tests plus traceability: per-package unit and fixture tests (positive and negative), an efficacy
  corpus at `test/efficacy/corpus/T1071.004-dns-c2-beacon/` (`scenario.yaml` plus `expected.yaml`), and a spectrace
  `// spec:` marker on the rule test referencing the new scenario.
- README: document DNS as the third telemetry stream and the newest component, with encrypted-DNS and failure-mode
  handling noted as roadmap.

### Not in this change (deferred)

- Enabling the DNS proxy by default in the host app's `activate` flow: tracked in the separate
  `2026-06-09-dns-proxy-on-by-default` change (implemented in the host-app/Swift PR), so the `host-app-extension-manager`
  spec lands with the code that flips the default.
- A DNS-proxy `.mobileconfig` for unattended/MDM pre-approval: the spike showed the proxy enables without it on an
  approved host. No `release-packaging` change here.
- Encrypted DNS (DoH/DoT) visibility, a domain-reputation feed, a full DGA model, and NXDOMAIN / beacon-cadence signals:
  their own later changes.
- The `endpoint-event-collection` DNS-capture contract is unchanged; the observed `dns_query` payload already matches
  the existing spec, so this change references it without modifying it.
