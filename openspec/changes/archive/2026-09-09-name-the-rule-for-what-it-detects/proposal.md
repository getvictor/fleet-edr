# Name the rule for what it detects

## Why

`dns_c2_beacon` was titled "DNS C2 beacon" and detects no beaconing. It measures no periodicity and cannot: it holds no state between event batches, by design, because the server is stateless.

What it actually detects is three conjuncts: a process launched from a temporary or world-writable path, which earlier resolved a domain, and then connected to one of the addresses that lookup returned, within thirty seconds. The rule's own summary already describes this correctly as the classic malware-phoning-home shape. Only the name disagreed with the code.

The name misled in both directions. An operator reading the catalog reasonably assumed beaconing was covered, and it is not. An analyst triaging an alert titled "beacon" reasonably assumed periodicity had been observed, and it had not.

It also misled authors, which is how it was caught. The exported rule file for this rule was once written from the name rather than the code and came out claiming an `interval_regularity_and_entropy` algorithm, a description about scoring "regularity of query intervals", and a false-positive entry about polling agents with fixed check-in intervals. None of that has ever existed. A wrong name generates wrong documentation.

## What changes

The canonical name becomes "Suspicious process phoning home", which describes what the rule actually observes: a process whose exec path is suspicious, looking a domain up and then connecting to what it resolved.

"Dropped payload" was the first choice and is also wrong, for the same reason the old name was. The rule checks that the exec path sits under a temporary or world-writable prefix, or contains `..`. It sees no file creation and no download, so it cannot say the binary was dropped there; a tool that legitimately lives in `/tmp` trips the same gate. Naming an observation the evaluator does not make is precisely the defect this change exists to fix, and review caught it being reintroduced.

**The identifier stays `dns_c2_beacon`.** Alerts, exclusions and `detection_rule_settings` all key on it, so changing it would strand existing per-rule settings and orphan historical alerts: a real cost paid for nothing an operator sees. The identifier is a stable key; the name is what people read, and only the name was wrong. That divergence is now stated in the rule's doc comment so a later reader finds a decision rather than apparent drift.

Released changelog entries keep the old name. They record what the rule was called when those versions shipped, and rewriting them would misdescribe history.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/internal/catalog/dns_c2_beacon.go` and its rule pack, `docs/detection-rules.md`, the demo trigger script and seed corpus, `README.md`
- Closes #752
