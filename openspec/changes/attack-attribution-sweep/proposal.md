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

Two are decided and recorded rather than changed:

- `sensor_tamper` keeps **T1562.001**. It separates the one benign cause it knows about, an upgrade cutover, by how fast capture resumes, and that separation is the observation. Recorded as not airtight, with what would change the answer, so the next audit does not start from scratch.
- `osascript_network_exec` keeps **T1059.002 + T1105**, and the issue's reason to narrow it does not hold against the code. There is one place a finding is constructed and reaching it requires a curl or wget among the osascript's descendants. The shebang shape is how the temp-exec is recognised, not a second arm that skips the download, so every finding has an observed fetch behind it.

Per-finding narrowing needs no further work either. `dns_c2_beacon` is the one rule with a union to narrow and it already does.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/internal/catalog/`, regenerated `docs/detection-rules.md`, `docs/attack-navigator-layer.json` and `server/rules/internal/catalog/pack/*.yml`, and the L6 corpus scenario renamed to the sub-technique it now exercises

**The coverage change, which the issue asks to be reviewed as one deliberate diff.** Two techniques drop from covered to monitor-only in the Navigator layer, because the only rules left covering them ship in monitor mode:

| Technique | Before | After |
|---|---|---|
| T1059 | covered, by `suspicious_exec` + `shell_network_connect` + four imported | monitor-only, the four imported |
| T1566.001 | covered, by `shell_from_office` + one imported | monitor-only, the one imported |
| T1059.004 | `shell_from_office` | `shell_from_office` + `shell_network_connect` + `suspicious_exec` |
| T1105 | six rules | four; the two that never observed a transfer come off |

That is a genuine reduction in claimed coverage and it is the point: we were reporting that we alert on Spearphishing Attachment because a rule fires on a shape phishing often produces.
