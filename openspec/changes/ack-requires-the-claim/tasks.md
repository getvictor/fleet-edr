# Tasks

- [x] The claim returns its stamp; the ack requires it and reports whether the claim was still held.
- [x] The caller skips its post-acknowledgement work when it lost, and logs it, which is also the first signal that leases are being exceeded.
- [x] A partial match counts as lost, since the result is only ever used to mean "this attempt processed the batch exactly once".
- [x] The stale comment in recordMonitorMatches that documented this gap now records that it is closed.
- [x] Mutation-tested: the condition removed, and the affected-row count ignored.
