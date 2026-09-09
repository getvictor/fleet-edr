# Tasks

## 1. Finish the archived change

- [x] 1.1 Retire `Policy editor with audit reason gate`, confirming first that no such component remains in `ui/src`.
- [x] 1.2 Restore the three application-control requirements, written against the shipped components.
- [x] 1.3 Correct the archived text where it disagrees with what is built: the version column, where the host-group count is shown, the rules table's columns, and the paste-many reason gate.

## 2. Fix the bug the restoration surfaced

- [x] 2.1 Remove the `CERTIFICATE` / `PATH` gate from the paste-many flow; the server, the schema and the single-rule modal all accept them.
- [x] 2.2 Correct the two code comments that claimed the gate was in lockstep with `AddRuleModal`.
- [x] 2.3 Replace the test that pinned the gate with one pinning the corrected behaviour, and mutation-test it.

## 3. Re-attach the traceability

- [x] 3.1 Move the three markers in the E2E policy-editor spec onto the requirements that now carry those scenarios.
- [x] 3.2 Rewrite that spec's header, which named the retired requirement's scenarios.
