# Browse the rules a deployment runs

Issue #1001, first of two changes. This one makes the rule catalogue reachable and readable. The second adds writing, validation, deletion, and rollback on the same page.

## The problem

Writing your own detection rules is a headline capability, and the only way to reach it is the API. There is not even a catalogue to find: the routes carry `/rules/:ruleId` but no `/rules`, and the top navigation has no Rules entry. A rule's page is reachable only by deep link from an alert or the coverage page, so an operator cannot browse what the deployment detects.

## What changes

- **A Rules entry in the top navigation**, gated on `rule_content.read`, opens a catalogue of every rule the deployment runs. Each row shows the rule's name, identifier, severity, and the mode it runs in, marked when an operator set it. It also says whether the rule shipped with the product or was written on this deployment, with the upstream author credited for a shipped rule. The catalogue searches by name or identifier and filters to shipped rules or the deployment's own.
- **A rule's page shows its rule document as written**, for an operator with `rule_content.read`. Rules loaded from the stored corpus are Sigma YAML with an `x-engine` block, and the file is how an operator sees exactly what a rule matches. A rule built into the server says it is not loaded from a stored document rather than showing an empty panel. An operator without the permission sees the page as before, with no panel that could only fail.

Shipped-versus-own comes from the origin the rules API already reports, which the server derives from provenance recorded when a document is stored. It is not inferred from a document's path, because a rule's identity is its file stem and its directory carries no meaning.

## Out of scope here

Editing, creating, validating, deleting, and rolling back rules: the second change.
