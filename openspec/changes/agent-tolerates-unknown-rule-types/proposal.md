# The agent tolerates a rule type it does not recognise

## Why

`2026-06-02-add-application-control` specified that the executor FAIL a `set_application_control` payload whose `rules` array carries a `rule_type` it does not recognise, forwarding nothing. That requirement was restored to the canonical spec by the #905 repair, because the archive had dropped it. Restoring it surfaced that the system does not behave that way, and should not.

The executor validates `policy_id`, `policy_version` and the shape of `rules`, then forwards the snapshot. The extension applies the entries it understands and skips the rest with a warning, and its own comment says so. The server validates `rule_type` when the rule is created.

So the unknown-type case only arises when the agent is OLDER than the server that wrote the policy. Failing the whole payload there turns an additive server change into a loss of application control on every host still running the previous agent: no rules apply at all, instead of the rules that agent does understand. The partial-enforcement-with-a-warning behaviour is the better failure, and it is the one that ships.

## What changes

- The requirement states that an unrecognised `rule_type` does not fail the payload, and why.
- The scenario requiring the executor to fail is removed.

No code change: this aligns the specification with behaviour that is already correct.

## The other restored-but-unimplemented behaviour went the other way

Review found a second one in the same requirement: `Forwarded successfully` says the result carries the policy identifier, the version, AND the count of rules, and the executor returned only the first two. That one is fixed in code on this PR rather than removed here, and the difference is the point rather than a coincidence.

Removing a restored requirement is right when the specified behaviour is worse than what ships. Failing a payload on an unrecognised `rule_type` is worse: it costs application control on every older host. Reporting how many rules were forwarded is better than what ships: the version alone says which policy a host took, not how much of it, and a host on the right version with the wrong rule count is exactly what an operator reconciling a rollout needs to see. So the test is not "does the code already do this" but "which of the two is the behaviour we want", and the answers differ.

This carries no delta of its own because it changes no specification. The requirement already says the count is reported; the #905 repair restores that sentence to canonical, and the code is brought into line with it.

## Impact

- Affected specs: `agent-command-executor`
- Affected code: none
