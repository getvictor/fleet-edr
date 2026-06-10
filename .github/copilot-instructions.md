# Copilot review instructions: Fleet EDR

Fleet EDR is a standalone macOS EDR (Swift Endpoint Security extension + Go agent + Go server + React UI + JSON event schema). When reviewing a pull request, apply these repo-specific checks in addition to the usual ones.

## Always flag: behavior changes that do not update the spec

The behavioral contract lives in `openspec/specs/**/spec.md` and is enforced against tests by `tools/spectrace`. If a PR changes observable behavior (a detection rule under `server/rules/internal/catalog/**`, the event wire schema `schema/events.json`, the detection DDL / persistence semantics under `server/detection/**`, an API/wire shape, or the extension's emitted events) and does NOT update `openspec/specs/**` (and ideally add an `openspec/changes/` proposal), flag it as a missing spec update. A new or renamed `### Requirement:` / `#### Scenario:` MUST also have at least one test carrying its canonical `spec:<id>` marker, and a renamed scenario MUST update every marker referencing the old slug.

The `OpenSpec sync` CI gate has a `no-behavior-change` opt-out (label or `[no-behavior-change]` in the title) for the case where a behavior-path file changed but the change is genuinely non-behavioral (comment, refactor, gofmt, dep bump). If a PR uses that opt-out but the diff DOES change observable behavior, flag it: the assertion is wrong and the spec is required. The opt-out is never a license to skip the spec for a real behavior change.

## Repo conventions (do not flag these as issues)

- The project builds on Go 1.26+ (see `go.mod`); modern language and standard-library features through 1.26 are in-bounds. Integer range (`for i := range N` where `N` is an `int`) compiles and is the preferred form, and newer stdlib such as `strings.SplitSeq` / `bytes.SplitSeq` is available. Do NOT claim these "don't compile" or "break Go 1.22+": that has been a recurring false positive (#239, #344).
- No em-dashes in code, comments, or docs, and no spaced hyphen (`-`) standing in for one: reword (prefer shorter sentences) or use `:`. A hyphen is fine only unspaced in a compound word (`per-IP`) or as a list marker. Flag a spaced `-` aside as a violation; it is enforced by `tools/dash-lint`.
- Line wrap is 140 characters for Go; SwiftLint allows 150. Do not flag Go/Swift lines under those limits. Markdown is NOT hard-wrapped (Prettier `proseWrap: never`, enforced by `task lint:md:prose`); do not flag long Markdown prose lines or single-line paragraphs.
- The macOS deployment target is 26.x and the product minimum is macOS 13+ (ADR-0002); do not flag missing `#available` guards for macOS-13+ APIs (BTM, ESF muting/inversion, etc.).

## Security surfaces to scrutinize

- Endpoint Security callback threads must never block on the network: any `SecStaticCodeCheckValidity` / code-signing evaluation on the ES path must pass `.noNetworkAccess`.
- C pointers imported from the ESF SDK that are `_Nonnull` (e.g. `es_event_btm_launch_item_add_t.item`) are non-optional in Swift; an `x?.pointee` guard on them does not compile. `_Nullable` ones (e.g. `instigator`, `app`) do need a guard.
