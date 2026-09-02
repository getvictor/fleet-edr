# Tasks

- [x] Move the shared ancestor walk to `shellchain.go` as free functions over a `shellChainRule` interface, so both rules drive one walk with their own id, resolver and window.
- [x] Add `shell_network_connect` with the outbound-connect arm, shipping in `monitor` and registering its own algorithm and window param.
- [x] Trim `suspicious_exec` to the temp-path arm: one evaluation pass, one declared event type, and documentation that no longer describes the arm it lost.
- [x] Move the fourteen network-arm tests unchanged except for the rule under test, so a test that passed before the split and passes after is the evidence the split preserved the behaviour.
- [x] Replace the precedence test with one pinning the two-alert outcome, so #777 has a baseline it must deliberately change.
- [x] Assert exclusions do not leak in either direction between the two rules.
- [x] Fixtures for the new rule: a positive, the local-resolver DNS negative, and an inbound-flow negative.
- [x] Update the registration-order, algorithm-name and exclusion-surface pins, and regenerate the rule pack, the reference and the ATT&CK layer.
- [x] Confirm on a running server that a chain doing both raises two alerts, one per rule.
