## 1. Single source of truth for supported match types

- [x] 1.1 Add `SupportedExclusionMatchTypes() []ExclusionMatchType` to the `api.Rule` interface.
- [x] 1.2 Implement it on all 10 catalog rules (the 4 consuming rules return their consulted set; the other 6 return nil).
- [x] 1.3 Add `SupportedExclusionMatchTypes` to `api.RuleMetadata` and populate it in `service.List()` and `bootstrap.catalogList.List()`.
- [x] 1.4 Surface `supported_exclusion_match_types` on `GET /api/rules` (always an array, never null).

## 2. Signature-based parent exclusions for suspicious_exec

- [x] 2.1 Extend the shared `codeSigningJSON` struct with `signing_id`.
- [x] 2.2 Extend `suspicious_exec.parentExcluded` to match the parent's `team_id` / `signing_id` (from `Process.CodeSigning`) and `cdhash` (from `Process.CDHash`), after the existing `parent_path_glob` check.

## 3. Create-exclusion validation

- [x] 3.1 Add a per-rule capability map + `SetRuleExclusionSupport` setter to the detection-config `Service`.
- [x] 3.2 Validate `(rule_id, match_type)` in `Service.CreateExclusion`: reject an unknown rule id, a rule that accepts no exclusions, and an unsupported match type, as `ErrInvalidRequest` (HTTP 400) with a clear message.
- [x] 3.3 Wire the capability map from bootstrap, built from the live rule set.

## 4. UI

- [x] 4.1 Add `supported_exclusion_match_types` to the `RuleDocEntry` type.
- [x] 4.2 Filter the exclusion editor's match-type picker to the selected rule's supported set, in display order; disable it until a rule is selected; reset the selection when the rule changes.

## 5. Tests

- [x] 5.1 Anti-drift guard: pin each rule's declared set, and a recording resolver proving `suspicious_exec` queries exactly its declared set.
- [x] 5.2 `suspicious_exec` signature-exclusion suppression (team_id / signing_id / cdhash) and non-suppression of an unsigned lookalike.
- [x] 5.3 Service validation cases (unsupported pair, unknown rule, no-exclusion rule, unset map skips).
- [x] 5.4 Handler: `GET /api/rules` includes the field; create rejection message reaches the 400 body.
- [x] 5.5 UI: picker offers only the supported set and resets on rule change.

## 6. Spec + verification

- [x] 6.1 OpenSpec delta (this change).
- [x] 6.2 `go build ./...`, `go vet -tags integration ./...`, `go test ./server/rules/... ./server/detection/...`, `cd ui && npm test`, `task lint:go`, `task lint:dashes`, `task lint:md:prose`, `openspec validate --all --strict`, `spectrace check --strict`.
