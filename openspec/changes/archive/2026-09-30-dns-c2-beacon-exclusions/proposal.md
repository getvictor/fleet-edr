# Let an operator waive a known-good phone-home

## Why

`dns_c2_beacon` declared no exclusion match types, so its false positives could not be waived one at a time (issue #1154). The only levers were monitor mode or a severity override, and both silence the rule for every host and every flow. It is also the rule that can raise critical.

Two open alerts on the dogfood deployment were this rule and both were benign: a load generator and a local server build, each run from a temporary directory and each connecting to a service the operator runs.

## What changes

The rule consults five exclusion match types:

- `domain`, against the domain the process resolved. It matches that name and its subdomains, which is already the defined meaning of the type. It is the right tool when what the operator trusts is the destination.
- `path_glob`, `team_id`, `signing_id` and `cdhash`, against the connecting process. These are the dimensions `suspicious_exec` already matches its parent on, through one shared helper, so `signing_id` is matched qualified by the signing team and a planted ad-hoc binary cannot claim a vendor's exclusion.

## Existing data

None is affected. While the rule declared no match types, creating an exclusion for it was rejected, so no stored exclusion names `dns_c2_beacon`. Widening the set makes new exclusions possible and changes the meaning of none.

## Not changed

The suspicion gate, the lookup-then-connect join, and the severity escalation are unchanged. An excluded flow produces no finding and is not counted as abandoned.
