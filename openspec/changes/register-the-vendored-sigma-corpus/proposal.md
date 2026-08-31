# Register the vendored Sigma corpus, in monitor mode

## Why

Issue #764. #763 vendored the SigmaHQ macOS corpus and proved 66 of its 69 rules are runnable; nothing registered them, so they were carried but never evaluated. #811 gave a rule the ability to declare the mode it operates in. This connects the two.

The rules must not alert on arrival. This project did not write them and no operator here has seen what they do on real fleets. Sixty-six unfamiliar rules raising alerts on day one is how a catalog loses trust in a week, and once trust is gone the alerts get muted wholesale, including the ones that were right.

## What changes

The corpus moves out of `testdata` into the package so it is embedded in the binary rather than read from a path, and every rule in it is registered and declares `monitor`.

Registering rules that raise nothing creates a way to overstate the product, so the three operator-facing surfaces are made to distinguish them. The rule catalog already reports `default_mode` (#811). The ATT&CK coverage export now scores a technique covered only by non-alerting rules apart from one an alerting rule covers, in a distinct colour, because that document is read while evaluating the product and this change would otherwise take it from 13 techniques to 64 on the strength of rules that raise nothing. The generated rule reference gains the same distinction in its index and per-rule tables.

A vendored rule's declarative form is the file this repository vendored. The exported pack therefore skips them rather than rendering a second description of the same rule in this project's format, and the per-rule export endpoint serves the vendored bytes, which is also what an operator can diff against SigmaHQ.

Guards that encode this project's authoring standards, a title without a parenthetical and a claimed ATT&CK technique, are scoped to the rules it authors. Upstream does not write to our style guide. Each vendored rule that falls outside one is pinned by name, so scoping costs visibility rather than buying silence.

## Impact

66 rules begin evaluating. None alerts: each records what it would have fired on until an operator promotes it. Per-rule smoke fixtures are tracked separately under #773, which is already scoped as a regression fixture per detection rule.
