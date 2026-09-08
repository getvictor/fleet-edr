# Tasks

## 1. Establish what the product actually does

- [x] 1.1 Confirm the executor forwards rather than validating `rule_type` (`agent/commander/executor.go`).
- [x] 1.2 Confirm the extension skips an unrecognised entry and applies the rest (`ApplicationControlStore.swift`).
- [x] 1.3 Confirm the server validates `rule_type` at rule creation, so the case is already gated where it can be.

## 2. Remove the clause whose specified behaviour is worse than what ships

- [x] 2.1 State the tolerant behaviour in the requirement and remove the scenario that contradicts it.

## 3. Implement the clause whose specified behaviour is better than what ships

- [x] 3.1 Report the count of rules forwarded alongside the policy identifier and version.
- [x] 3.2 Assert the count in the retargeted `Forwarded successfully` test, and mutation-test it.
- [x] 3.3 Scrub the `runSetApplicationControl` doc comment, which advertised a two-field result.

## 4. Correct the validation clauses the restored text described loosely

- [x] 4.1 State that `policy_id` and `policy_version` are validated as positive integers, not that `policy_id` is "non-empty".
- [x] 4.2 State that `rules` is validated as a JSON array, and that the individual entry shape deliberately is not.
- [x] 4.3 Rename the invalid-payload scenario to cover the four shapes its tests already pin, and repoint those four markers.
