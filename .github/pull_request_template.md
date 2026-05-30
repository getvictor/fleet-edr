<!-- Keep this short. Delete sections that do not apply. -->

## What & why



## Checklist

- [ ] **OpenSpec updated for behavior changes.** If this PR changes observable behavior (a detection rule, the event
      wire schema, persistence semantics, an API/wire shape, or an emitted event), `openspec/specs/**` is updated (and
      an `openspec/changes/` proposal added), with a `spec:<id>` test marker for any new/renamed scenario. If this is a
      refactor / comment / perf change with no behavior delta, N/A (add the `skip-openspec` label or `[skip-openspec]`
      in the title if the OpenSpec-sync gate trips on a scoped path).
- [ ] Tests added/updated for the change (unit / integration / efficacy / UI as applicable).
- [ ] Agent/extension change touching ESF, XPC, or the event wire format: exercised on a live macOS VM before RC
      (flagged below).

## VM / RC notes (if applicable)


