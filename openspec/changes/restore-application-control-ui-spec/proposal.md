# Restore the application-control UI spec the archive dropped

## Why

`2026-06-02-add-application-control` did two things to `web-ui`: it ADDED three requirements describing the Application Control screen, and it REMOVED `Policy editor with audit reason gate`, the requirement for the two-textarea blocklist editor that screen replaced. Its own removal note says the legacy `PolicyEditor` "is deleted in the same change".

The archive applied neither. The canonical `web-ui` spec still carries the retired requirement, describing an editor that stages "paths and SHA-256 hashes" and has not existed since, and carries none of the three requirements describing the UI that shipped in its place. The component really is gone: nothing under `ui/src` mentions a blocklist or a staging editor.

This is the clearest real loss the #905 audit has found. The canonical spec describes deleted UI and does not describe shipped UI, and the traceability gate stayed green throughout because the E2E spec that drives the current screen was still carrying markers for the retired requirement's scenarios.

## What changes

- REMOVE `Policy editor with audit reason gate`, finishing what the archived change specified.
- ADD three requirements written against the shipped components, not the archived text.
- Move the three markers in `test/e2e/tests/qa/policy-editor.spec.ts` onto the requirements they actually exercise. That spec drives `/ui/app-control/policies/<id>` and the app-control REST surface; only its markers were stale.

### Corrections against what is built

The archived text is not reproduced verbatim, because parts of it are stale:

- The policies list carries a **version** column the archived text does not mention.
- The archived text says the **detail view** shows which host groups the policy is assigned to. It does not; the assignment count is in the **list**, in an Assignments column. The requirement now says where it actually is.
- The rules table's columns are pinned to what the table renders: type, identifier, severity, custom message, last modified, actions.
- Paste-many is additionally gated on a non-empty audit reason, which the archived text omits.

## A bug this surfaced

Writing the paste-many requirement forced the question of which rule types it accepts, and the two UI surfaces disagreed. `AddRuleModal` offers all six types with `available: true`; `PasteManyModal` gated `CERTIFICATE` and `PATH` as "coming soon" and refused to submit a row carrying either, on a comment claiming the two sets were kept "in lockstep". They were not, and the server has always accepted all six: `rule_type` is a six-value `ENUM` in `00001_initial.sql`, `validate.go` validates `CERTIFICATE` identifiers, and the handler's own error message lists all six.

So an operator could create a `CERTIFICATE` or `PATH` rule one at a time but could not paste one. The gate is removed rather than specified, since specifying it would have written a defect into the canonical tree.

## Impact

- Affected specs: `web-ui`
- Affected code: `ui/src/components/ApplicationControl/PasteManyModal.tsx`, `ui/src/components/ApplicationControl/pasteInference.ts`, their tests, and `test/e2e/tests/qa/policy-editor.spec.ts`
- Operator-visible: pasting a list containing an absolute path or a leaf-certificate hash now works instead of blocking submission behind a "coming soon" label.
