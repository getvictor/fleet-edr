# The agent tolerates a rule type it does not recognise

## Why

`2026-06-02-add-application-control` specified that the executor FAIL a `set_application_control` payload whose `rules` array carries a `rule_type` it does not recognise, forwarding nothing. That requirement was restored to the canonical spec by the #905 repair, because the archive had dropped it. Restoring it surfaced that the system does not behave that way, and should not.

The executor validates `policy_id`, `policy_version` and the shape of `rules`, then forwards the snapshot. The extension applies the entries it understands and skips the rest with a warning, and its own comment says so. The server validates `rule_type` when the rule is created.

So the unknown-type case only arises when the agent is OLDER than the server that wrote the policy. Failing the whole payload there turns an additive server change into a loss of application control on every host still running the previous agent: no rules apply at all, instead of the rules that agent does understand. The partial-enforcement-with-a-warning behaviour is the better failure, and it is the one that ships.

## Three restored clauses did not match the product, and they do not resolve the same way

Restoring the requirement surfaced three, not one. Which way each goes is the judgement worth reviewing, and the test is not "does the code already do this" but "which of the two is the behaviour we want".

| Restored clause | Ships? | Resolution |
| --- | --- | --- |
| Fail the payload on an unrecognised `rule_type` | No | Removed by this delta |
| Report the count of rules forwarded | No | Implemented in the PR carrying this delta |
| `policy_id` is "non-empty", `rules` unmentioned | No | Corrected by this delta |

**Unknown `rule_type` is worse than what ships**, for the reason above, so the scenario requiring the executor to fail is removed and the requirement states the tolerant behaviour and why.

**The rule count is better than what ships.** `Forwarded successfully` says the result carries the policy identifier, the version, AND the count of rules; the executor returned only the first two. The version alone says which policy a host took, not how much of it, and a host on the right version with the wrong rule count is exactly what an operator reconciling a rollout needs to see. So this one is fixed in code rather than removed from the spec. It needs no delta of its own: it changes no specification, because the requirement already says the count is reported and the #905 repair restores that sentence to canonical.

**The validation clauses were simply wrong about the checks.** The text said the executor validates that `policy_id` is "non-empty", which is the vocabulary of a string; `policy_id` is an `int64` and the executor rejects any value at or below zero. And it did not mention `rules` at all, though the executor refuses a payload whose `rules` is absent or is not a JSON array before the extension bridge is touched. Both corrected, and the invalid-payload scenario renamed to cover what its four tests already pinned: malformed JSON, a zero `policy_id`, a zero `policy_version`, and a `rules` value of the wrong shape.

## What changes

- The requirement states that an unrecognised `rule_type` does not fail the payload, and why. The scenario requiring the executor to fail is removed.
- `policy_id` and `policy_version` are stated as positive-integer checks, and `rules` as a JSON-array check.
- The requirement states what the executor deliberately does NOT validate, the shape of the individual rule entries, which is the same boundary the unknown-rule-type clause draws.
- The invalid-payload scenario is renamed to match the four shapes its tests pin, and those four markers move with it.

## Impact

- Affected specs: `agent-command-executor`
- Affected code: none by this delta. The PR carrying it adds the rule count to `runSetApplicationControl`'s result, which is required by the restored canonical requirement rather than by anything proposed here, and is an additive change to what the server stores as the command result.
