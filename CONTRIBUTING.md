# Contributing to Fleet EDR

Thanks for your interest in contributing. This guide covers what an external contributor needs to get a change reviewed and merged.

If you are reporting a security vulnerability, **do not open a public issue**. Follow [`SECURITY.md`](SECURITY.md) instead.

## Before you start

- Read [`README.md`](README.md) for the quick start (toolchain pins, MySQL setup, dev server).
- Read [`docs/architecture.md`](docs/architecture.md) so you know which component (system extension, network extension, agent,
  server, UI) your change touches.
- For non-trivial changes, open an issue first describing the problem you are solving. We would rather discuss the approach
  before you write the code than reject a finished PR for being out of scope.

## Toolchain

Pinned in [`.tool-versions`](.tool-versions). Install [`mise`](https://mise.jdx.dev/) (or `asdf`) and run `mise install` to
match local, CI, and AI-agent sandbox versions. Pre-commit hooks live in [`lefthook.yml`](lefthook.yml); install once with
`lefthook install`.

CI is the backstop, not the floor. If a check fails locally fix it locally; do not push hoping CI will pass.

## Style and conventions

| Surface | Source of truth |
| --- | --- |
| Go | [`docs/go-conventions.md`](docs/go-conventions.md), [`.golangci.yml`](.golangci.yml) |
| TypeScript / React | `ui/eslint.config.js`, `ui/tsconfig.json` (strict mode + `eslint-plugin-security`) |
| Swift | [`.swiftlint.yml`](.swiftlint.yml) (run with `--strict`) |
| C bridge | [`.clang-tidy`](.clang-tidy), [`.clang-format`](.clang-format) |
| GitHub Actions | `actionlint` + `zizmor` (security audit) |
| Markdown / prose | Sentence case headings, wrap at 140 chars, no em-dashes |
| Commits | Imperative mood, focused scope, one logical change per commit |

If a linter disagrees with a specific change, prefer fixing the code over disabling the rule. Suppression with a `nolint` /
`eslint-disable` / `swiftlint:disable` directive needs a one-line justification on the same line.

## Tests

Run `task test` before pushing. Targeted runs: `task test:go`, `task test:ui`. Use subtests (`t.Run`) and table-driven cases
in Go. Integration tests hit a real MySQL on port 3317; do not mock the database in store-layer tests.

Coverage is measured by SonarCloud; the new-code coverage gate is 80%. PRs that add code without adding tests will fail the
gate.

## Pull requests

- Branch off `main`. Keep the diff focused; large refactors should be split into reviewable chunks.
- Write a PR description that explains the *why*, not just the *what*. Link the issue it closes.
- A PR is ready to merge when CI is green, the SonarCloud quality gate is green, and at least one maintainer has approved.
- Do **not** add `Co-Authored-By` lines to commits. AI-assisted code is welcome; the assistant is a tool, not a co-author.
- Sign your commits if you can (`git commit -S`); we do not require this today, but plan to.

## Security-sensitive changes

Touching auth, crypto, the network extension, or the ingestion pipeline triggers extra scrutiny:

- Reviewers will look for the threat-model implications. Read [`docs/threat-model.md`](docs/threat-model.md) and call out the
  STRIDE category your change affects in the PR description.
- Constant-time comparisons for any token / hash check (`subtle.ConstantTimeCompare`).
- No new untrusted-input -> SQL / shell / log-injection sinks.
- Add a test that exercises the failure path, not just the happy path.

## Reporting bugs

For non-security bugs, open a [GitHub issue](https://github.com/getvictor/fleet-edr/issues/new) with:

- Affected component (server, agent, system extension, network extension, UI).
- Version or commit SHA.
- Reproduction steps.
- Expected vs. actual behaviour.
- Relevant logs (`log show --predicate 'subsystem == "com.fleetdm.edr"'` for macOS components, server stdout for the daemon).

## License

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE) and that you have the right
to grant that license. We do not require a CLA today; we may add a DCO sign-off requirement before opening the project to
broader external contribution.
