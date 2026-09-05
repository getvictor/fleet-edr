# Tasks

- [x] A boot-time pass credits alerts whose origin was never recorded, for vendored rules only, under `DoOnceIfLeader` so exactly one replica runs it and none waits.
- [x] Our own rules are excluded, so the distinction migration 00012 preserves between "raised before attribution existed" and "raised by us" survives.
- [x] Projections are excluded, so this project does not claim authorship of an operator's own policy entry.
- [x] The scope decision is a named function with its own tests, because both exclusions are invisible in the SQL and irreversible if wrong. Mutation-tested: dropping either exclusion, or reading `OriginOf` instead of `AlertOriginOf`, is caught.
- [x] Only rows with an empty origin are touched, so an attribution already recorded is never overwritten and a second pass is a no-op. Both are pinned, and mutation-tested.
- [x] A deployment running no vendored rules issues no statement at all, rather than a malformed one with no branches.
- [x] A failure is logged and does not stop the server.
- [x] The rewrite is batched, because alerts carries no index this predicate can use (rule_id sits third in the dedup key, behind source and host_id), so an unbounded UPDATE would hold row locks across a table scan at boot. The loop is covered by seeding one more row than a batch holds; removing the LIMIT itself is a knowingly missed mutation, since it changes lock footprint rather than any observable result.
- [x] Alerts from a rule the deployment no longer runs stay uncredited, and that limit is stated rather than worked around.

