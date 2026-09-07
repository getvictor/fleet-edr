# Let an operator see and roll back the rule pack

## Why

Retention and rollback landed with nothing able to invoke them. An operator could neither see which generation of shipped rules their deployment was running nor restore the previous one, so the recovery path existed only in the store.

## What changes

Two routes on the existing rule-content surface, which is where per-rule tuning already lives and where an operator looking at a noisy rule already is.

Reading reports the generation installed, the generation the build carries, and which **rules** differ. By identity rather than by path, because identity is what an operator recognises and what their tuning is keyed on: a rule that moved directories upstream is the same rule, and reporting it as one removed plus one added would be noise dressed as a change.

Rolling back requires a reason and records its own audit action, rather than reusing a document change. It replaces every shipped rule at once, so an audit trail calling it a document edit would understate what happened. Shipped rules withheld because the operator has taken that rule over ride back in the response and into the audit payload, because the deployment is deliberately not running content it was offered and nothing else would say so.

## Impact

- `rulecontent` declares a pack-lifecycle port; `rules` consumes it, as it already does for authoring, so the operator surface can call it without `rulecontent` depending on the rules context (ADR-0021).
- The port is bound to the running build's own corpus in `cmd/main`, which is what lets both methods take no arguments: reading the build's pack is the implementation's business, not the caller's.
- Editing rule content requires the admin role, reading it admin or senior analyst, unchanged from the document routes beside these.
