# Recovery failing is not an adversary technique

## Why

`sensor_recovery_failed` declared T1562.001 (Impair Defenses: Disable or Modify Tools) on a condition it explicitly cannot attribute to anyone, and whose documented causes are this product's own software.

The rule contradicted itself. Its `Limitations` say it reports that recovery gave up and NOT why the provider stopped. Its `Description` sends an analyst to look at the host application and the system configuration daemon, which are ours. Both outcome values, `enable_failed` and `enable_ineffective`, describe our repair mechanism failing rather than anyone acting against us.

The observed base rate agrees. The 37.8-hour providerless episode on 2026-07-17 was the `enable_ineffective` shape, caused by a Settings disable-then-enable leaving the network extension with no filter or DNS sessions: an OS-interaction bug, and the common cause of this alert in practice.

## Where the claim actually landed, which is not where the issue said

The issue was filed about the ATT&CK coverage export a customer reads during an evaluation. That half is **already handled**: the rule has since been classified a health signal, which keeps it off the coverage export, off `GET /api/rules`, and out of the generated rule reference.

What the claim still reached is every **alert** this rule raises. The finding declares no techniques of its own, so alert persistence falls back to the rule's declared list and stamped T1562.001 onto the row an analyst reads. That is the surface this fixes, and it is a narrower claim than the issue makes.

## What changes

- `sensor_recovery_failed` declares no technique, as an empty slice rather than nil, which is the interface's stated contract for "no mapping".
- Its alert TEXT no longer names one either. The description is copied onto the alert verbatim, so removing the structured mapping alone would have left `(MITRE T1562.001)` in the sentence the analyst actually reads. The operational explanation is untouched.
- The requirement says what a technique declaration means, so the next rule faces the question deliberately: declare one only for something observed, and declaring none is a complete mapping rather than a gap.

## What does not change

The alert keeps its Critical severity, its title and its operational explanation, and stays a separate rule from `sensor_tamper`. The issue asks for the text to be unchanged and for only the attribution to change; those read together mean the attribution comes out of the text too, since it was inside it. The measured case for the split is unaffected: on one host a stop was repaired 35.7s later and the host was fine while another exhausted every attempt and left the host blind, and both produced word-for-word identical `sensor_tamper` alerts.

Whether this signal belongs on a health surface rather than in the detection feed is a larger question, tracked separately.

## What this does not do

It does not sweep the other rules, and on merge the tree does not fully satisfy the requirement this delta states. `shell_from_office` declares Spearphishing Attachment on a chain where it observes no delivery vector, and `suspicious_exec` declares Ingress Tool Transfer where it observes an execution rather than a transfer. Both are #755, which audits every mapping at once and reviews the resulting coverage change as one deliberate diff.

The requirement still lands here rather than with that sweep, which makes the sweep a correction to a stated rule rather than a matter of taste, and lets this change fix the least arguable case on its own: the one rule whose own documentation names this product as the likely cause of what it reports.

That shortfall is recorded here rather than in the requirement itself, because the requirement is archived into the canonical spec and outlives the transition. A sentence naming two noncompliant rules would become false the moment #755 lands, and stale spec prose is the failure this project keeps paying for. The proposal is the record of what was true when the change was made, which is exactly what this is.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/rules/internal/catalog/sensor_recovery_failed.go`
