# Repository rulesets

Source of truth for the branch + tag protection rules on this repo. The
JSON files in this directory are the request-body shape the GitHub
Repository Rulesets API expects. They are NOT auto-applied. Treat them
as a review/audit artifact: any change to live ruleset state should be
mirrored by a PR that updates the matching JSON, and `git blame` on
these files is the change log.

## Why no auto-apply

Auto-apply would require giving a CI workflow `Repository
administration: Write` scope, which is broad enough that a compromised
workflow can disable the very rulesets it's supposed to enforce. For a
single-maintainer project the security cost outweighs the convenience
benefit. Once the project either adds a second maintainer or acquires
an audit-driven mandate (SOC 2, etc.), upgrade the
[`rulesets-drift.yml`](../workflows/rulesets-drift.yml) workflow's
`gh api` calls from GET to PUT, grant `Repository administration:
Write`, and treat each ruleset JSON as the canonical source. The diff
job becomes an apply job; files in this directory do not change.

## Why no drift-detection by default

The workflow [`rulesets-drift.yml`](../workflows/rulesets-drift.yml)
ships in this repo but is **opt-in**: it short-circuits with a notice
unless a `RULESETS_READ_PAT` secret is configured. Reading rulesets via
the API requires `Repository administration: Read`, which the workflow's
default `GITHUB_TOKEN` cannot grant. Enabling drift-detection means
creating a fine-grained PAT, storing it inside a `rulesets-drift`
GitHub Environment (so the token is scoped the same way as the
`release-signing` and `sonarcloud` environments already used in this
repo), and rotating it on the same cadence as any other long-lived
credential. That's a real ongoing cost, so we leave the choice to the
maintainer rather than making it implicit. Setup steps are in the
workflow's header comment.

## Updating a ruleset

1. Edit the JSON in this directory.
2. Apply the change to GitHub via the API or UI:
   ```sh
   gh api -X PUT \
     /repos/getvictor/fleet-edr/rulesets/<id> \
     --input .github/rulesets/main.json
   ```
   Look up the ruleset id with
   `gh api /repos/getvictor/fleet-edr/rulesets`.
3. Open a PR with the JSON change. If `RULESETS_READ_PAT` is configured,
   the drift-detect workflow runs automatically and confirms the live
   state now matches. Otherwise it exits early with a setup notice.

## Files

| File | What it pins |
| --- | --- |
| `main.json` | Default-branch (currently `main`) protection: PR required, status checks must pass, no force-push, no delete. |
| `tags-v.json` | All `v*` tags: no delete, no force-move, no update. Pairs with the `release-signing` GitHub Environment that gates the release workflow on `v*` refs. |

## Required status checks

The `required_status_checks` list in `main.json` names checks that ALWAYS
run on every PR. Workflows with path filters are intentionally NOT in
the list because GitHub blocks merges on required checks that did not
run, even when the path filter would have skipped them. The currently
excluded path-filtered workflows are `c-lint.yml`, `openapi-lint.yml`,
`swift-lint.yml`, `go-lint.yml` (golangci-lint), `go-nilaway.yml`,
`go-vulncheck.yml` (server + agent), `ts-lint.yml` (Lint and test),
and `pkg-dryrun.yml` (Pkg build dry-run). They still run on PRs that
touch their relevant paths, but their pass/fail is advisory only. To
promote any of them to required, first rewrite the workflow to always
start and short-circuit inside its job.
