# Sweep every ATT&CK mapping against what the rule observes

## Why

Closes #755. It audits all eleven first-party detections and finds the same fault in five of them: the technique describes what the rule is ABOUT rather than what it OBSERVED.

`Techniques()` feeds `GET /api/attack-coverage` and `docs/attack-navigator-layer.json`, which are read during procurement. An unearned mapping is a coverage claim that does not survive being probed, and the two worst were claims of ALERTING coverage on the strength of an inference.

#754 fixed the least arguable case, a rule whose own documentation named this product's components as the likely cause of what it reports, and stated the requirement the rest are wrong against. This is that sweep.

## What changes

Three mappings are corrected:

- `shell_from_office` drops **T1566.001** (Spearphishing Attachment). It observes an Office process spawning a shell, never an email, an attachment, or any delivery. The document could have arrived on a share or a USB stick. The phishing narrative stays in the description, where prose can say "usually" and a coverage claim cannot.
- `suspicious_exec` drops **T1105** (Ingress Tool Transfer) and moves **T1059** to **T1059.004**. It observes a binary executing from a world-writable directory, not anything arriving; and the middle link is matched against the shell path set, so the sub-technique is known rather than guessed.
- `shell_network_connect` does the same. This is the question #776 left open when it split the rule: an outbound connection is not a transfer, and naming an application-layer protocol would need one to be observed.

Two more are corrected, and they are the two the issue called arguable and asked to have decided either way:

- `osascript_network_exec` drops **T1105**. The first pass kept it, reasoning that a finding is unreachable without a curl or wget among the osascript's descendants. That reasoning is about the wrong thing: the check matches a downloader by PATH and inspects nothing else, so `curl --help` beside an unrelated temp exec reaches the same finding. What is observed is that a downloader ran; the transfer is the inference. Holding this rule to a lower standard than `suspicious_exec` because its chain feels more incriminating is how the whole class got here.
- `sensor_tamper` drops **T1562.001**. It separates the one benign cause it knows about, an upgrade cutover, by how fast capture resumes, and that separation is real. It is not an attribution. The distinction the sweep turns on is whether a technique names a BEHAVIOUR or an ACTOR'S ACTION: T1059.004 names a behaviour, so seeing the shell is seeing the technique whoever started it; Impair Defenses names somebody impairing defenses, and a crash that stays down produces this finding exactly.

Per-finding narrowing needs no further work. `dns_c2_beacon` is the one rule with a union to narrow and it already does.

The alerts are unchanged throughout. Severity, title and text are untouched on every rule here; only the coverage claim moves.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/internal/catalog/`, regenerated `docs/detection-rules.md`, `docs/attack-navigator-layer.json` and `server/rules/internal/catalog/pack/*.yml`, and the L6 corpus scenario renamed to the sub-technique it now exercises

**The coverage change, which the issue asks to be reviewed as one deliberate diff.** Two techniques drop from covered to monitor-only in the Navigator layer, because the only rules left covering them ship in monitor mode:

| Technique | Before                                            | After                                                           |
| --------- | ------------------------------------------------- | --------------------------------------------------------------- |
| T1059     | covered, by two authored rules plus four imported | monitor-only, the four imported                                 |
| T1566.001 | covered, by `shell_from_office` plus one imported | monitor-only, the one imported                                  |
| T1105     | covered, by two authored rules plus three imported | monitor-only, the three imported                                |
| T1562.001 | covered, by `sensor_tamper` alone                 | **absent from the layer**                                       |
| T1059.004 | `shell_from_office`                               | `shell_from_office`, `shell_network_connect`, `suspicious_exec` |

That is a genuine reduction in claimed coverage and it is the point: we were reporting that we alert on Spearphishing Attachment because a rule fires on a shape phishing often produces, and on Impair Defenses because a capture provider went quiet.

**T1562.001 leaves the export entirely**, since `sensor_tamper` was the only rule claiming it once #754 landed. Worth seeing before merge rather than after: the tamper ALERT is untouched and an operator still learns their sensor stopped, but the Navigator layer a customer reads no longer says we detect Impair Defenses. Re-earning it is a change to the rule's predicate rather than to its technique list, by observing the actor: the process that stopped the provider, or a policy change that did.
