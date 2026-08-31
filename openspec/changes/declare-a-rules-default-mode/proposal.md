# A rule declares the mode it operates in absent configuration

## Why

Issue #764 imports sixty-six upstream Sigma rules and requires that none of them alert until an operator promotes it. Sixty-six unfamiliar rules going straight to alert is how a detection catalog loses operator trust in a week, and once trust is gone the alerts get muted wholesale.

The mode column already exists in `detection_rule_settings`, but it records what an OPERATOR set. There is no notion of a rule's own default: `Snapshot.ResolveRuleMode` returns `alert` whenever no setting matches. Defaulting sixty-six rules to monitor by seeding a row each would put policy in data. Every fresh install and every test database would have to reproduce it, a rule added later would need another migration, and an operator deleting a row would silently promote the rule to alerting.

## What changes

A rule may declare the mode it operates in when nothing is configured for it, through an optional interface in the same shape as the existing `NonDetection` and `AlgorithmNamer` declarations. A rule that declares nothing operates in `alert`, which is what every rule did before, so no existing rule changes.

The declared default is what applies when no setting matches, and also when no configuration service is wired at all. A configured setting always overrides it: an operator who promotes a rule must not be overridden by the rule's own opinion.

One existing behaviour changes. A stored mode this build cannot interpret used to resolve to `alert`; it now resolves to the rule's declared default. An unreadable instruction is not an instruction to alert, and alerting would take a rule whose author declared monitor and promote it on the strength of a value we could not read.

The declared default is reported by `GET /api/rules`, because the rule-settings surface lists only settings an operator created: a rule left at its own monitor default would otherwise appear on no surface and read as alerting.

## Impact

No rule declares a default yet, so no rule's behaviour changes. `GET /api/rules` gains an additive `default_mode` field, `alert` for every rule today.

This does NOT close the existing requirement that a disabled rule be listed by `GET /api/rules` "with its mode indicated". That asks for a mode resolved from configuration, which the catalog surface still does not report; `default_mode` is the rule's own declaration and says so. Tracked separately.
