# Tasks

## 1. Scope the detail flow read to one generation

- [x] 1.1 Add `ProcessFlowFilter` and `NetworkEventsForGeneration` to the visibility `EventArchive`, documenting the two-arm attribution rule on the type.
- [x] 1.2 Implement the read in the ClickHouse store, factoring the `(pid, pidversion)` predicate out of the alert-chain timeline scope so both share one implementation.
- [x] 1.3 Mirror the read in the in-memory archive so the fake and the store cannot diverge.
- [x] 1.4 Call it from `GetProcessDetail`, passing the generation's `pidversion`, a wide pruning bound, and the tight window for the legacy arm.
- [x] 1.5 Widen the exited-process window upper bound to 60s and record why in a comment.

## 2. Pin the behavior

- [x] 2.1 Reproduce #716: a flow ingesting 3.5s after its generation's exit ingest must surface under that generation.
- [x] 2.2 Assert the mis-attribution is gone: the same flow must NOT surface under a sibling generation of the same pid.
- [x] 2.3 Cover the legacy arm: a flow with no `pidversion` still surfaces via the window, and `pidversion` 0 is a real generation rather than an absent one.
- [x] 2.4 Exercise the predicate as SQL against real ClickHouse, not only against the fake.
- [x] 2.5 Verify the tests fail when the identity arm is reverted.

## 3. Make the owning generation addressable

- [x] 3.1 Accept an optional `pidversion` query param on the detail endpoint, parsed strictly so a malformed value is a 400 rather than a silent fallback to a different generation.
- [x] 3.2 Thread it to `GetProcessDetail` and resolve by `GetProcessByPIDVersion` when set, keeping the as-of read byte-identical when absent.
- [x] 3.3 Pass the node's `pidversion` from the UI panel, omitting the param when the node carries none, and add it to the fetch effect's dependencies so switching generations refetches.
- [x] 3.4 Pin that a named generation of a re-exec chain is reachable while the as-of read alone still resolves the newest, and that an unknown `pidversion` is a 404 rather than a substitution.

## Review follow-ups (PR 718)

- [x] 5.1 Keep the payload guard when the process record carries no generation, so a legacy record cannot claim a flow that names a generation. Flip the integration expectation that pinned the opposite.
- [x] 5.2 Bound the scan from the query time rather than the record's own start, so a long-lived process can still show recent flows.
- [x] 5.3 Cap the flow read and report truncation, in the API and in the panel.
- [x] 5.4 Bound identity matches by the generation's padded event-time life, so a repeated generation value does not serve one generation another's flows.
- [x] 5.5 Reject a present-but-empty `pidversion` rather than treating it as absent.
