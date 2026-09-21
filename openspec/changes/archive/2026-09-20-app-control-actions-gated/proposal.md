# Application control offers only the rule changes the operator may make

Issue #1056. The application-control policy page is gated on `application_control.read`, and then shows every mutating control to anyone who gets in: Add rule, Paste many, and each rule's Promote or Move to Detect, Edit, Disable or Enable, and Delete. Each of those calls needs a mutation permission of its own, so a `senior_analyst`, who reads application control and holds no mutation verbs, could open any dialog, type an audit reason, submit, and only then be told 403.

The UI already has the seam for this. `useCan()` reads the server-computed permission set and other pages gate their controls on it; `ui/src/permissions-core.ts` simply had no app-control mutation actions to gate on.

## What changes

- **Four action identifiers are added to the UI's registry**: `application_control.rule_create`, `rule_update`, `rule_delete` and `rule_bulk_upsert`. They are the same strings the server's chokepoint enforces and the audit log records, which is what keeps the UI from growing its own idea of who may do what.
- **Each control is hidden without the permission its own call needs.** Promote or Move to Detect, Edit, and Disable or Enable all PATCH the rule, so one permission gates the three. Delete and the two header controls have one each.
- **A read-only operator gets no Actions column**, rather than a header over four empty cells, and the empty-policy message stops telling them to click a button they cannot see.

## What this does not claim

This is presentation only, and the server's authorization chokepoint remains the sole boundary (ADR-0012). Hiding a control stops the page offering work the server will refuse; it grants nothing and withholds nothing. An operator whose permission set is unknown, which is what an older server returns, still sees every control and leans on the 403 path, because an absent permission set must never read as a denial.

## Out of scope

- Policy-level controls. The New policy button is permanently disabled pending multi-policy support, so there is nothing to gate yet.
- The modals themselves. They are reachable only through the controls gated here.
