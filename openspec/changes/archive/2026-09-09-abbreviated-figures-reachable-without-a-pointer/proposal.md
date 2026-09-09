# Abbreviated table figures are reachable without a pointer

## Why

The detection-tuning table abbreviates two columns and keeps the precise figures in a native `title`. A native tooltip opens on pointer hover only, so a sighted keyboard user and anyone on a touch device cannot reach them at all.

These are the figures the columns exist for. The Cost column's whole purpose is finding the rule that is slow, and "usually fast, occasionally terrible" is a real answer that lives entirely in the worst-case number. An operator on a tablet gets the mean and nothing else.

A matching `aria-label` meant assistive technology was already fine, which is exactly why the gap was easy to miss: the accessibility tree was complete while the visible interaction was not.

## What changes

Both columns move the precise figures behind one disclosure, activated by click, tap, or keyboard.

- The visible cell keeps its abbreviated form. At a thousand rules the column has to stay scannable, so the fix is a disclosure rather than showing everything.
- The full sentence stays in the document at all times, visually hidden until expanded, and remains attached to the control as its description. That is what keeps assistive technology whole: rendering it only when expanded would take away what the `aria-label` used to give, in the course of fixing access for everyone else.
- Both columns use the same control, so the pair cannot diverge. Fixing one and leaving the other would put two adjacent columns on different interactions, which is worse than the gap.

## Impact

- Affected specs: `web-ui`
- Affected code: `ui/src/components/DetectionConfig/DetectionConfig.tsx`, `DetectionConfig.scss`
- Closes #902
