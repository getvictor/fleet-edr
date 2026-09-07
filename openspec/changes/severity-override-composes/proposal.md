# A severity setting adjusts what a rule decided, it does not replace it

## Why

A per-rule severity setting overwrote a rule's computed severity, so any conditional escalation the rule performed was discarded.

`dns_c2_beacon` raises a finding from high to critical when the resolved domain reads as algorithmically generated. The engine applied the operator's setting afterwards and unconditionally, so an operator who found the rule noisy and set it to low got low for a high-entropy phone-home and low for an ordinary one. The escalation was not reduced, it was erased, and the erased population is precisely the one that operator would most want to keep visible. The tuning action produced the opposite of the intended outcome, silently.

Nothing was false about any individual field. The defect is that the two populations became indistinguishable, which is why the property to fix is an ORDERING rather than a set of values.

## What changes

- A rule with a conditional escalation declares a risk modifier instead of reporting a finished severity. The setting replaces the base; the modifiers apply on top.
- A modifier carries a risk DELTA rather than a destination. A destination is the same value however the rule was tuned, which is the same defect from the other side: the escalated findings would snap back to the rule's own opinion and ignore the operator's.
- A modifier declares the techniques its condition implies alongside the risk, and the engine stamps them. A rule cannot then add a technique for a condition without saying what the condition is worth, and an operator retuning the amount is re-weighting that technique knowingly.
- Risk is bounded to the scale, so escalations on an already-critical finding stay critical rather than running off the end.

The banding is Elastic's, which is the one most operators reading this product already have a feel for: low 0-21, medium 22-47, high 48-73, critical 74-100. Each band's representative value is its mid-point rather than its edge, so a delta lands inside a band instead of teetering on a boundary. `dns_c2_beacon`'s DGA escalation is 25, chosen so the untuned rule reports exactly what it always has.

This is the mechanism the declarative rule format specifies as `x-engine.risk_modifiers`, but the engine fix stands alone and does not depend on it.

## What this deliberately does not do

The risk number is internal. Alerts are still persisted, served and displayed as a band, because introducing a numeric score to the alert schema, the API and the UI is a much larger change than the defect requires, and the acceptance criteria are about ordering rather than about exposing a score.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/detection/api/types.go`, `server/detection/internal/engine/engine.go`, `server/rules/api/types.go`, `server/rules/internal/catalog/dns_c2_beacon.go`, `server/detection/testkit/replay.go`
