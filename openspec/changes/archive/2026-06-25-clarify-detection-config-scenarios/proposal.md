# Clarify the detection-config admin scenarios (no behavior change)

## Why

Release-review of the `detection-tuning-author-and-modes` archive (PR #505) surfaced three internal-consistency nits in the scenarios under the `web-ui` "Detection configuration admin views" requirement. The requirement description is correct; the scenarios that illustrate it drifted in wording when monitor was dropped as an operator-selectable mode:

- One scenario is titled "Disabling or monitoring a rule requires an operator reason" and its steps still talk about "reducing a rule's alerting" via monitor, even though the requirement states reason capture happens when an operator disables a rule (monitor is no longer operator-selectable).
- That same scenario asserts severity-only edits "does not prompt for a reason", which reads as "no reason at all" and contradicts the requirement's "MAY use a system-generated reason".
- The "Monitor is not an operator-selectable mode" scenario sets a single WHEN ("a rule has no persisted monitor setting") but its THEN/AND cover two different rules (no-monitor and legacy-monitor), mixing two preconditions in one branch.

This is a spec-clarity fix only. No engine, API, or UI behavior changes; the implementation already matches the corrected scenarios.

## What changes

- Rename the scenario "Disabling or monitoring a rule requires an operator reason" to "Disabling a rule requires an operator reason" and rewrite its WHEN to "set a rule's mode to disabled". The non-trigger clause becomes "does not require an operator-supplied reason (a system-generated reason is recorded instead)", aligning with the requirement's system-generated-reason allowance.
- Rewrite the "Monitor is not an operator-selectable mode" scenario so the WHEN is the operator opening a rule's mode control, with the no-monitor and legacy-monitor cases split cleanly across THEN and AND.
- Update the matching spectrace marker in `ui/src/components/DetectionConfig/DetectionConfig.test.tsx` to the renamed scenario ID. The test assertions are unchanged.

## Impact

- Affected specs: `web-ui` (Detection configuration admin views): two scenarios reworded, one renamed.
- Affected code: `ui/src/components/DetectionConfig/DetectionConfig.test.tsx` (one spectrace marker comment retargeted). No production code, no migration, no behavior change.
