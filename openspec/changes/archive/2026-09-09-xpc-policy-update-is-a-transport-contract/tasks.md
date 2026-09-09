# Tasks

## 1. Narrow the requirement

- [x] 1.1 Rewrite `Inbound policy update` to the transport contract, deferring replacement and persistence to the snapshot requirement that specifies them in full.
- [x] 1.2 Correct the scenario that named a `policy.update` message the extension does not accept.
- [x] 1.3 Keep the reject-without-disarming property, which nothing else states.

## 2. Re-attach the traceability

- [x] 2.1 Move the marker for the renamed scenario and rewrite the test comment that repeated the persistence claim.

## 3. Record the requirement that only looks dead

- [x] 3.1 Verify `agent-xpc-receiver/Outbound policy push routed to active connection` against the code before removing it: the legacy symbols are gone but `Dispatcher.SendApplicationControl` and `ErrNoConnector` are the same contract, with live tests.
- [x] 3.2 Record it as an exception rather than deleting a live, tested requirement.
