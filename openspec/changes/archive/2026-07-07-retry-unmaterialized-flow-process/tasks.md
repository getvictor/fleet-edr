# Tasks

## 1. Tighter flow-process grace

- [x] 1.1 Add `flowProcessMaterializationGrace` (5s compiled constant) to the catalog and refactor the age check into a shared `withinGrace(ingestedAtNs, nowNs, grace)` helper that `withinMaterializationGrace` now delegates to.
- [x] 1.2 Update the `resolveSubjectProcess` doc comment so it no longer claims dns_c2_beacon's flow resolution keeps the silent skip.

## 2. Retryable flow-process miss

- [x] 2.1 In `dns_c2_beacon.evalEvent`, when `resolveFlowProcess` misses and the connect's ingest age is inside `flowProcessMaterializationGrace`, raise `api.ErrProcessNotYetMaterialized`; otherwise keep the historical silent skip.

## 3. Tests

- [x] 3.1 Rule level: a young outbound connect with no flow process row raises the sentinel; a past-grace connect skips silently; a zero ingest stamp (fixture replay) skips silently.
- [x] 3.2 Confirm the existing fixtures (positive beacon, negatives) and `resolveFlowProcess` precedence tests still pass unchanged.

## 4. Spec reconciliation

- [x] 4.1 Reword the `retry-unmaterialized-process-events` delta (requirement clause + residual-risk prose) so the batched canonical archive does not contradict the new flow-process requirement.
