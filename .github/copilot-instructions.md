# Copilot review instructions: Fleet EDR

Fleet EDR is a standalone macOS EDR (Swift Endpoint Security extension + Go agent + Go server + React UI + JSON event schema). When reviewing a pull request, apply these repo-specific checks in addition to the usual ones.

## Always flag: behavior changes that do not update the spec

The behavioral contract lives in `openspec/specs/**/spec.md` and is enforced against tests by `tools/spectrace`. If a PR changes observable behavior (a detection rule under `server/rules/internal/catalog/**`, the event wire schema `schema/events.json`, the detection DDL / persistence semantics under `server/detection/**`, an API/wire shape, or the extension's emitted events) and does NOT update `openspec/specs/**` (and ideally add an `openspec/changes/` proposal), flag it as a missing spec update. A new or renamed `### Requirement:` / `#### Scenario:` MUST also have at least one test carrying its canonical `spec:<id>` marker, and a renamed scenario MUST update every marker referencing the old slug.

The `OpenSpec sync` CI gate has a `no-behavior-change` opt-out (label or `[no-behavior-change]` in the title) for the case where a behavior-path file changed but the change is genuinely non-behavioral (comment, refactor, gofmt, dep bump). If a PR uses that opt-out but the diff DOES change observable behavior, flag it: the assertion is wrong and the spec is required. The opt-out is never a license to skip the spec for a real behavior change.

## Repo conventions (do not flag these as issues)

- Go 1.22+ integer range (`for i := range N` where `N` is an `int`) compiles and is the project's preferred form. Do NOT claim it "doesn't compile": that has been a recurring false positive.
- No em-dashes in code, comments, or docs (use `:` or `-`).
- Line wrap is 140 characters for Go and Markdown; SwiftLint allows 150. Do not flag lines under those limits.
- The macOS deployment target is 26.x and the product minimum is macOS 13+ (ADR-0002); do not flag missing `#available` guards for macOS-13+ APIs (BTM, ESF muting/inversion, etc.).

## Security surfaces to scrutinize

- Endpoint Security callback threads must never block on the network: any `SecStaticCodeCheckValidity` / code-signing evaluation on the ES path must pass `.noNetworkAccess`.
- C pointers imported from the ESF SDK that are `_Nonnull` (e.g. `es_event_btm_launch_item_add_t.item`) are non-optional in Swift; an `x?.pointee` guard on them does not compile. `_Nullable` ones (e.g. `instigator`, `app`) do need a guard.
