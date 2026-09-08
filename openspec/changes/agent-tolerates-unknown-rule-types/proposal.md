# The agent tolerates a rule type it does not recognise

## Why

`2026-06-02-add-application-control` specified that the executor FAIL a `set_application_control` payload whose `rules` array carries a `rule_type` it does not recognise, forwarding nothing. That requirement was restored to the canonical spec by the #905 repair, because the archive had dropped it. Restoring it surfaced that the system does not behave that way, and should not.

The executor validates `policy_id`, `policy_version` and the shape of `rules`, then forwards the snapshot. The extension applies the entries it understands and skips the rest with a warning, and its own comment says so. The server validates `rule_type` when the rule is created.

So the unknown-type case only arises when the agent is OLDER than the server that wrote the policy. Failing the whole payload there turns an additive server change into a loss of application control on every host still running the previous agent: no rules apply at all, instead of the rules that agent does understand. The partial-enforcement-with-a-warning behaviour is the better failure, and it is the one that ships.

## What changes

- The requirement states that an unrecognised `rule_type` does not fail the payload, and why.
- The scenario requiring the executor to fail is removed.

No code change: this aligns the specification with behaviour that is already correct.

## Impact

- Affected specs: `agent-command-executor`
- Affected code: none
