# Tasks

## 1. Interface and rules

- [x] 1.1 Add `DisplayName() string` to `server/rules/api` `Rule` interface with a doc comment establishing it as the single canonical name.
- [x] 1.2 Implement `DisplayName()` on all 10 catalog rules; set each `Doc().Title` to `r.DisplayName()`.
- [x] 1.3 Set each rule's `Finding.Title` to `r.DisplayName()` (both `suspicious_exec` arms collapse to the one title; `application_control_block` keeps its computed per-block title).
- [x] 1.4 Add `DisplayName()` to the test stub rules so they satisfy the interface.

## 2. Guard against re-drift

- [x] 2.1 Catalog test: for every rule assert `DisplayName()` non-empty, `Doc().Title == DisplayName()`, and the name carries no parenthetical.
- [x] 2.2 Fixture-replay harness asserts `Finding.Title == DisplayName()` for every replayed rule.
- [x] 2.3 Each non-replayed positive-detection test asserts `Finding.Title == DisplayName()`; `suspicious_exec` arm coverage re-pinned on the Description.

## 3. Docs

- [x] 3.1 Regenerate `docs/detection-rules.md` (`go run ./tools/gen-rule-docs`).

## 4. Spec + validation

- [x] 4.1 Spec delta adds the "Canonical rule naming" requirement + scenario; `registry_test.go` carries the spectrace marker.
- [ ] 4.2 `openspec validate canonical-rule-naming --strict` and `task lint:dashes` pass.
