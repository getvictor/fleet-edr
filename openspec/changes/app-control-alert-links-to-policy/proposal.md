# Route an application-control alert to the policy that blocked

## Why

An application-control alert's title is plain text. A detection alert's title links to the rule that raised it; an app-control alert's does not, so an analyst who sees `Application blocked: /usr/bin/curl` has no way to reach the rule that denied it or the policy that owns that rule.

The current behaviour is correct as far as it goes. `ProcessTree.tsx` links a title only when the rule catalog documents the rule, because linking an undocumented id lands the analyst on "Unknown rule", which is worse than no link. App-control alerts carry `app_control:<n>`, which has never been in the catalog. That reasoning justifies not using the catalog route; it does not justify having no route.

PR #974 made the demo's block alert cite a policy rule that actually exists, so both ends of the link now exist and nothing joins them.

## What changes

- A new `GET /api/v1/app-control/rules/{id}` returns a single rule, including the `policy_id` that owns it. `PATCH` and `DELETE` already live at that path, so this completes the resource rather than adding a lookup endpoint beside it.
- The alert breadcrumb recognises the `app_control:` prefix and links the title to the owning policy.
- Detection alerts keep the catalog link. An alert whose rule is neither, such as `sensor_recovery_failed`, keeps the plain-text fallback.

## What does not change

The catalog route, the plain-text fallback, and the rule-id format. No stored data changes: the policy is resolved at read time from the rule id the alert already carries.

## Out of scope

Anchoring the specific rule within the policy detail page. That page has no per-rule anchor today, and adding one is a separate change; the link lands on the policy that owns the rule, which is the reachability this fixes.
