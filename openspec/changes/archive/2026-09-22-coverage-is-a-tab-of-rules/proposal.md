# Put coverage beside the rules it is computed from

## Why

Coverage and the rule catalogue are two views of one thing. The coverage layer is built entirely from the registered rules: each technique row names the rules covering it and links to them, and a rule's detail links back. They sit in the navigation as peers of Alerts and Hosts, which says they are separate places, and an operator reading one has no way to reach the other except by going back to the top navigation.

They were also, until now, separately reachable: the catalogue asked for an authorization the coverage view did not, so an analyst could hold one and not the other. That is no longer true, and it was the reason not to put them together.

## What changes

Coverage becomes a tab of Rules rather than an entry of its own. The two share a sub-navigation rendered on both, and the Rules entry stays active while the operator moves between them.

The paths do not move. Coverage keeps `/coverage` rather than becoming `/rules/coverage`, because a static segment there would rank above the `/rules/{id}` a rule detail uses, so a rule whose identifier was `coverage` would become unreachable, and because every existing link and bookmark to `/coverage` keeps working.

The parent keeps the name Rules rather than becoming Detections, because this deployment already has a Detection tuning surface; a Detections section beside it would say that tuning is inside it.

## Impact

- Affected specs: `web-ui`
- One fewer top-level navigation entry. Nothing becomes unreachable: `/coverage` is still a route, still linked from a rule's detail, and now reachable from the catalogue as well.
