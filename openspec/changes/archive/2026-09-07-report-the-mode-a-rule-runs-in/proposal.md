# Report the mode a rule runs in, and let an operator put one back in monitor

## Why

Issue #810, and the first part of #813.

The `Operator toggling of individual rules` requirement ends with a clause the product does not meet: a rule whose global mode is `disabled` must stay listed by `GET /api/rules` "with its mode indicated". That endpoint reports `default_mode`, which is the mode the rule DECLARES. A setting overrides a declaration, so a rule an operator disabled is listed looking exactly like a rule that alerts. The scenario carrying that clause has two tests and neither asserts it, which is why it read as covered: spectrace gates on a scenario having a marker, not on the test exercising every clause of it.

The second half is a door that only opens one way. `MODES` in the admin table offers alert and disabled; monitor was left out by the detection-tuning-author-and-modes change, on the grounds that it was a legacy value on a handful of rows with no review surface. #764 overturned both halves: sixty-six imported rules now default to monitor, and reviewing them is the whole point of the mode. Because the table renders a rule's current mode even when it is not selectable, such a rule could be promoted to alert and then nothing could put it back. An operator who promotes a noisy rule and regrets it is precisely the case monitor exists for, and it was the one case the control could not express.

## What changes

`GET /api/rules` reports `mode`, the mode each rule runs in at global scope, and `mode_source`, whether a setting or the rule's own declaration produced it. `default_mode` stays: the two answer different questions, and a reader needs both to tell a rule that ships in monitor from one an operator moved there. Global scope is the whole question a catalog listing can answer, since it names no host.

The mode and its source come from one resolution through a new narrow read surface rather than a third return value on the engine's resolver. Two calls can straddle a config reload and report a mode from one snapshot with a source from another, which is a listing that contradicts itself.

The rule detail view reports the mode in force rather than the declared default, and says which of the two it is. The admin table offers all three modes. Moving a rule to monitor stops it alerting, so it captures an operator reason like disabling does; moving a rule out of disabled into monitor does not, because the rule does more than it did. That is the same principle the surface already applied, stated once instead of as a special case for alert.

The engine's `Catalog()` method is deleted. It built a second `RuleMetadata` and its own comment recorded that production went through `rules.api.Lister` instead and that it survived only so engine tests compiled. Three review findings on #811 and #812 were fields it silently dropped, and this change adds two more fields it would drop.

## Impact

`GET /api/rules` gains two additive fields. Monitor becomes an operator-selectable mode, which reverses a product decision the web-ui spec states, so that requirement and its scenario are modified rather than left to contradict the UI.
