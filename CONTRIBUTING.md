# Contributing to Fleet EDR

Thanks for your interest in contributing. This guide covers what an external contributor needs to get a change reviewed and merged.

If you are reporting a security vulnerability, **do not open a public issue**. Follow [`SECURITY.md`](SECURITY.md) instead.

## Before you start

- Read [`README.md`](README.md) for the quick start (toolchain pins, MySQL setup, dev server).
- Read [`docs/architecture.md`](docs/architecture.md) so you know which component (system extension, network extension, agent, server, UI) your change touches.
- For non-trivial changes, open an issue first describing the problem you are solving. We would rather discuss the approach before you write the code than reject a finished PR for being out of scope.

## Toolchain

Pinned in [`.tool-versions`](.tool-versions). Install [`mise`](https://mise.jdx.dev/) (or `asdf`) and run `mise install` to match local, CI, and AI-agent sandbox versions. Pre-commit hooks live in [`lefthook.yml`](lefthook.yml); install once with `lefthook install`.

After cloning, run `task install`. The first `task lint:go` auto-builds the custom golangci-lint binary at `tmp/golangci-lint-custom` (via the `lint:install` dep) with the repo's in-tree `commentwrap` plugin baked in (see [`tools/comment-wrap-check/lint/`](tools/comment-wrap-check/lint/) and [`.custom-gcl.yml`](.custom-gcl.yml)); subsequent runs short-circuit via Taskfile's sources/generates. Editor integrations or terminal invocations of upstream `golangci-lint run` return "unknown linter: commentwrap" because the plugin only exists in the custom build; point your editor at `tmp/golangci-lint-custom` (or run `task lint:install` once to materialize it).

CI is the backstop, not the floor. If a check fails locally, fix it before pushing; do not push hoping CI will pass.

## Style and conventions

| Surface | Source of truth |
| --- | --- |
| Go | [`docs/go-conventions.md`](docs/go-conventions.md), [`.golangci.yml`](.golangci.yml) |
| TypeScript / React | `ui/eslint.config.mjs`, `ui/tsconfig.json` (strict mode + `eslint-plugin-security`) |
| Swift | [`.swiftlint.yml`](.swiftlint.yml) (run with `--strict`) |
| C bridge | [`.clang-tidy`](.clang-tidy), [`.clang-format`](.clang-format) |
| GitHub Actions | `actionlint` + `zizmor` (security audit) |
| Markdown / prose | [`.markdownlint-cli2.yaml`](.markdownlint-cli2.yaml) (run with `task lint:md`); sentence case headings, wrap at 140 chars, no em-dashes |
| Docs and versioning | [`docs/doc-versioning.md`](docs/doc-versioning.md): a user-facing change updates docs in the same PR (enforced by the `Docs sync` gate) |
| Commits | Imperative mood, focused scope, one logical change per commit |

If a linter disagrees with a specific change, prefer fixing the code over disabling the rule. Suppression with a `nolint` / `eslint-disable` / `swiftlint:disable` directive needs a one-line justification on the same line.

## Tests

Run `task test` before pushing. Targeted runs: `task test:go`, `task test:ui`. Use subtests (`t.Run`) and table-driven cases in Go. Integration tests hit a real MySQL on port 33307; do not mock the database in store-layer tests.

Coverage is measured by SonarCloud; the new-code coverage gate is 80%. PRs that add code without adding tests will fail the gate.

For the full picture (the seven-layer test pyramid, the fake-agent / headless-agent integration layer, the captured ESF event corpus, the detection-efficacy corpus, and spec-to-test traceability), see [`docs/testing-strategy.md`](docs/testing-strategy.md). Read it before adding a new detection rule, touching the agent / server wire format, changing anything in `extension/edr/`, or modifying a SHALL / MUST scenario under `openspec/specs/`.

## Pull requests

- Branch off `main`. Keep the diff focused; large refactors should be split into reviewable chunks.
- Write a PR description that explains the _why_, not just the _what_. Link the issue it closes.
- A PR is ready to merge when CI is green, the SonarCloud quality gate is green, and at least one maintainer has approved.
- **Behavior changes ship a spec delta.** A PR touching a detection rule, `schema/events.json`, or the detection DDL must ship an `openspec/changes/<name>/` proposal (`proposal.md`, `tasks.md`, and a delta `specs/<capability>/spec.md` written with `## ADDED / MODIFIED / REMOVED Requirements`). Do **not** hand-edit `openspec/specs/**` directly: that canonical tree is updated only by `openspec archive` after the PR merges. spectrace accepts a test marker that references a scenario declared in the in-flight delta, so you do not pre-merge the canonical spec. Two gates back this: `OpenSpec sync` enforces the PR touches `openspec/` (the delta satisfies it), and `OpenSpec validate` (`openspec validate --all --strict`) enforces every spec and delta is structurally well-formed. A no-behavior touch of those paths (comment, refactor, gofmt, dep bump) asserts `no-behavior-change` (label or `[no-behavior-change]` in the PR title) to clear the sync gate: an auditable claim a reviewer verifies, never a way to skip the spec for a real behavior change. The label is a one-time repo setup:

  ```sh
  gh label create no-behavior-change \
    --description "PR asserts it changes no observable behavior (clears the OpenSpec sync gate)" \
    --color ededed
  ```

- **After a spec-bearing PR merges, archive its change.** Run `openspec archive <name>` (without `--skip-specs`): it merges the delta into `openspec/specs/**` and moves the proposal to `openspec/changes/archive/`. Use `--skip-specs` only for a legacy change whose canonical spec was already hand-edited or a tooling/doc-only change. Never move or rename a change folder into `archive/` by hand.
- Do **not** add `Co-Authored-By` lines to commits. AI-assisted code is welcome; the assistant is a tool, not a co-author.
- Sign your commits if you can (`git commit -S`); we do not require this today, but plan to.

## Security-sensitive changes

Touching auth, crypto, the network extension, or the ingestion pipeline triggers extra scrutiny:

- Reviewers will look for the threat-model implications. Read [`docs/threat-model.md`](docs/threat-model.md) and call out the STRIDE category your change affects in the PR description.
- Constant-time comparisons for any token / hash check (`subtle.ConstantTimeCompare`).
- No new untrusted-input -> SQL / shell / log-injection sinks.
- Add a test that exercises the failure path, not just the happy path.

## Recurring maintenance

Maintainers run periodic codebase-hygiene sweeps (doc accuracy, stale implementation references, ADR audit, dead-code, etc.). Cadence, scope, and runnable prompts live in [`docs/maintenance/`](docs/maintenance/). External contributors do not need to run these, but PRs that surface issues those sweeps would catch are welcome.

## Reporting bugs

For non-security bugs, open a [GitHub issue](https://github.com/getvictor/fleet-edr/issues/new) with:

- Affected component (server, agent, system extension, network extension, UI).
- Version or commit SHA.
- Reproduction steps.
- Expected vs. actual behaviour.
- Relevant logs (`log show --predicate 'subsystem == "com.fleetdm.edr"'` for macOS components, server stdout for the daemon).

## License

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE) and that you have the right to grant that license. We do not require a CLA today; we may add a DCO sign-off requirement before opening the project to broader external contribution.
