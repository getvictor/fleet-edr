# Tasks

## 1. Read the claim

- [x] 1.1 Parse the host's reported components into the set of providers claiming to capture
- [x] 1.2 Treat a stopped, unknown, non-provider, or unreadable component as claiming nothing
- [x] 1.3 Gate each derived condition on its own provider's claim rather than on the host rollup

## 2. Delete the proxy

- [x] 2.1 Remove `ReferenceWindow`, the reference counts, and the nested-window type
- [x] 2.2 Collapse the archive read to one `TimeRange`, scanning 2 hours rather than 7 days
- [x] 2.3 Remove the two documented inaccuracies from the requirement and the package comment

## 3. Read paths

- [x] 3.1 Select the stored components in the list and detail queries, scanned into a row struct rather than a wire type
- [x] 3.2 Skip the archive read for a host claiming no capturing provider

## 4. Tests

- [x] 4.1 Rewrite the derivation tests around claims, including the disabled-provider case that used to need history
- [x] 4.2 Pin exactly which reported conditions count as a claim, asserted through `Derive` rather than an accessor
- [x] 4.3 Unreadable component payloads claim nothing
- [x] 4.4 Update the ClickHouse and detection integration fixtures to the per-provider components a real agent posts

## 5. Live QA

- [ ] 5.1 Confirm on the VM that a host claiming both providers, with one stream silenced, is still surfaced as degraded
