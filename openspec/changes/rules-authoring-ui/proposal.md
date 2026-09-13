# Write, check, delete, and roll back rules in the console

Issue #1001, second of two changes. The first (`rules-catalogue`) made the catalogue browsable and a rule's document readable. This one lets an operator change rules without leaving the console, on an API that is already built, permissioned, and audited.

## What changes

- **New rule** on the catalogue, for an operator with `rule_content.write`. The operator picks an identifier and edits a starting document. The page says at the point of creation that a new rule runs in monitor mode until promoted, and links to Detection tuning, so a quiet rule is not mistaken for a broken one.
- **Check before save.** The check calls the server's dry run, which answers with the loader's own verdict. A refusal is shown as the rule's problem, in the loader's words, and warnings are listed. Save is available only after a passing check of exactly the content on screen; any edit disarms it. Nothing is written that the dry run has not seen.
- **Every write asks for a reason**, which the API requires and records in the audit log. A write that loses a race with another change says to check again. A refusal on write shows the loader's reason.
- **Says when a change takes effect.** The server applies stored rules when it next reloads them, every 30 seconds, and every save and delete says so. The page a create opens waits for the new rule to be loaded instead of calling it unknown.
- **Edit and Delete** on the page of a rule the deployment wrote. Shipped rules are tuned in Detection tuning rather than rewritten here, where the next install of shipped content would meet the edit.
- **Shipped rules status and rollback** on the catalogue. It says whether the deployment runs the shipped rules this build carries and, when it does not, which rules differ. An operator who may write can roll back to the previous set with a reason. The result names any shipped rule not restored because a rule the deployment wrote now holds its identifier.

## Out of scope

Authoring assistance (templates beyond the starting document, field autocomplete, testing a draft against history) and renaming a rule, which is a new rule under a new identifier.
