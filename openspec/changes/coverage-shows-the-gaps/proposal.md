# Let coverage show what is not covered

## Why

The coverage view reports what the deployment detects and cannot report what it does not. It is built from the exported ATT&CK layer, and the layer carries a technique only when a rule covers it, so a technique nothing covers is absent rather than shown as missing. A reader can learn that sixty-four techniques are covered and cannot learn that three hundred and fifty-six apply to the platform this product watches, which makes the number a count rather than a fraction and the page a report rather than somewhere work starts.

Measured on the current catalogue: 356 of ATT&CK's 697 live enterprise techniques list macOS, 64 of those are covered, and 292 are not. None of those three figures could be read anywhere in the product.

The gap could not be computed at all before this change: the vendored technique table records a technique's name and tactics but not the systems ATT&CK lists it for, so every Windows and cloud technique in the enterprise matrix would have counted as a hole in a macOS sensor's coverage and buried the real ones.

## What changes

The technique table carries the platforms ATT&CK records, and the coverage view uses them to say what is missing: a count of in-scope techniques no rule covers, against how many are in scope, and a listing of them grouped by tactic in the same order the covered table uses.

An uncovered technique offers to be answered. An operator holding the permission to write rules is offered a link that opens the authoring surface with the technique already tagged, so the gap is closed by writing the rule for it rather than by remembering which one they were looking at.

## Impact

- Affected specs: `web-ui`
- `tools/attacktable` emits a platform list, and the vendored table is regenerated. No change to how rules are evaluated or to what the exported Navigator layer contains.
- A rule's detail stops offering "back to ATT&CK coverage" unconditionally. It offers the catalogue, which is where a rule is listed and where a reader browsing rules came from.
