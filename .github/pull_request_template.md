<!-- Keep this short. Delete sections that do not apply. -->

## What & why



## Checklist

- [ ] **OpenSpec updated for behavior changes.** If this PR changes observable behavior (a detection rule, the event
      wire schema, persistence semantics, an API/wire shape, or an emitted event), `openspec/specs/**` is updated (and
      an `openspec/changes/` proposal added), with a `spec:<id>` test marker for any new/renamed scenario. Only if this
      PR changes NO observable behavior (a comment / refactor / gofmt / dep bump that happens to touch a scoped path)
      may you assert `no-behavior-change` (label or `[no-behavior-change]` in the title) to clear the OpenSpec-sync gate.
      That is an assertion a reviewer will check, not a way to skip the spec for a real behavior change.
- [ ] Tests added/updated for the change (unit / integration / efficacy / UI as applicable).
- [ ] Agent/extension change touching ESF, XPC, or the event wire format: exercised on a live macOS VM before RC
      (flagged below).

## VM / RC notes (if applicable)


