# Tasks

- [x] 1.1 Confirm the executor forwards rather than validating `rule_type` (`agent/commander/executor.go`).
- [x] 1.2 Confirm the extension skips an unrecognised entry and applies the rest (`ApplicationControlStore.swift`).
- [x] 1.3 Confirm the server validates `rule_type` at rule creation, so the case is already gated where it can be.
- [x] 2.1 State the tolerant behaviour in the requirement and remove the scenario that contradicts it.

## 3. Correct the validation clauses the restored text described loosely

- [x] 3.1 State that `policy_id` and `policy_version` are validated as positive integers, not that `policy_id` is "non-empty".
- [x] 3.2 State that `rules` is validated as a JSON array, and that the individual entry shape deliberately is not.
- [x] 3.3 Rename the invalid-payload scenario to cover the four shapes its tests already pin, and repoint those four markers.
