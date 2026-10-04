## Why

A built-in rule's page said "there is no stored document to show", which reads as if the rule has no rule file at all. It does: the server renders one for every built-in detection (`GET /api/rules/{id}/export`), carrying the values the rule reads under `x-engine.params`. The console offered no way to see or download it, so the only route to a built-in rule's parameters was the API.

## What changes

- A built-in rule's page shows the rule file the server renders for it, read-only, and says the rule is built in and tuned through its mode and exclusions rather than edited here.
- Every rule page offers Download for the document it shows: the stored document under its own file name, or the rendered file as `<rule id>.yml`.

## Not changed

Built-in rules are still not editable, and their parameters still cannot be changed at runtime (tracked in #1208). The export endpoint and its authorization are unchanged.
