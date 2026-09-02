# Split suspicious_exec into a temp-exec rule and a network-connect rule

## Why

Issue #776. `suspicious_exec` fired on two chain shapes sharing one attribution chain: a non-shell process spawns a shell which, within 30 seconds, either execs from a world-writable directory **or** opens an outbound connection. That merged form is not how the industry models it, and the reasons are structural rather than stylistic.

Sigma cannot express it: one `logsource` per rule, and the arms span `process_creation` and `network_connection`. Elastic ships the equivalents as three separate macOS sequence rules, each requiring both events with no OR branch. CrowdStrike, Defender and SentinelOne all reconcile multi-signal chains at the incident layer rather than inside a rule.

The costs were concrete. A parent-path-glob exclusion added to silence a noisy CI shell on the connect arm also blinded the temp arm, because one rule id means one exclusion set. Neither arm could be promoted, tuned or severity-adjusted apart from the other. And with no equivalence forced between them, #713 was a gap in the connect arm alone: the exec-chain walk existed on the temp arm and not the connect arm, so `zsh -c 'curl ...'` was invisible while the identical `bash` form was detected.

## What changes

`suspicious_exec` keeps its id and its temp-path arm, so saved exclusions, existing alerts and per-rule settings survive. The outbound-connection arm becomes `shell_network_connect`, a new rule with a new id.

The new rule ships in `monitor`. Exclusions are keyed by rule id, so it starts unfiltered where the merged rule had been tuned; promoting it before its own false-positive rate is observed would re-raise every FP operators had already absorbed.

Each rule now declares exactly one event type. That is a correctness contract rather than tidiness: the engine dispatches on the declared set (#762), so a rule that declares a type it cannot act on is invoked for batches it will do nothing with, and one that under-declares is silently never invoked at all.

The ancestor walk is **not** split. Both rules answer the same question, "is there a shell in this process's ancestry, under a non-shell parent, within the window", and two copies would drift; #713 is what that drift looks like. It moves to `shellchain.go` as free functions over a small interface, which each rule satisfies with its own id, resolver and window.

## Impact

**A chain exhibiting both signals now produces two alerts, one per rule.** This is a deliberate, accepted cost. The merged rule's precedence (prefer the path-based finding) lived in a `seenShell` shared across its two evaluation passes, and cross-rule state is ruled out by ADR-0010. It is the only place we expect double alerts, it is pinned by a test rather than left incidental, and #777 is the real fix at the alert-grouping layer.

`shell_network_connect` inherits no exclusions. An operator who tuned `suspicious_exec` before the split must re-add anything that should silence the connect shape too; the rule's own limitations say so.

**Archive ordering, and this one is worse than usual.** This change MODIFIES `Registered rule catalog`, and **three** in-flight changes already modify the same requirement: `sensor-tamper-detection` (9 rules), `alert-when-sensor-recovery-gives-up` (10), and `catalog-lists-detections-only` (11). They happen to be cumulative supersets, so today the tree survives only because the largest archives last. This delta restates the 11-rule list plus `shell_network_connect` for the same reason, which means **it must archive after all three or its addition is silently dropped**. `openspec validate` does not catch this: a lost MODIFIED leaves a structurally valid spec that simply omits a registered rule. Tracked as #815; four competing restatements of one requirement is the strongest argument yet for fixing it.
