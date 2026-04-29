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

The `required_status_checks` list in `main.json` names every check that
must post a status before a PR can merge. GitHub treats a missing
required check (workflow never triggered) as a hard block and a skipped
required check (workflow triggered but its job's `if:` evaluated to
false) as success. The required list is comprehensive only when every
listed workflow always triggers on every PR.

To honor that rule, every conditionally-skipped workflow in this repo
uses the **gate-then-analyze** pattern:

```yaml
jobs:
  changes:
    name: Detect <kind> changes
    runs-on: ubuntu-latest
    outputs:
      relevant: ${{ steps.detect.outputs.relevant }}
    steps:
      - id: detect
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          # Inspect the PR's file list (or actor, etc.) and emit
          # relevant=true|false. Push/schedule/dispatch always emit true.

  <analysis>:
    name: <required-check-name>
    needs: changes
    if: needs.changes.outputs.relevant == 'true'
    # ... real work ...
```

The workflow has no `on.<event>.paths:` filter, so it always triggers.
The `changes` job inspects `gh api repos/.../pulls/<n>/files` and emits
a boolean. The analysis job is skipped via `if:` when the boolean is
false, and a job-level skip posts a `skipped` check that branch
protection treats as success. PRs that don't touch the relevant
language pay only the ~10s cost of the gate job; the workflow's full
cost (Xcode, golangci-lint, govulncheck, etc.) only runs when needed.

Workflows currently using this pattern: `go-lint.yml`,
`go-nilaway.yml`, `go-vulncheck.yml`, `ts-lint.yml`, `pkg-dryrun.yml`,
and `codeql.yml` (one gate job, three language outputs feeding three
analysis jobs).

`test.yml`'s `sonarcloud` job uses a simpler shape because its skip is
actor-based, not path-based. The job has `if: github.actor !=
'dependabot[bot]'`; on Dependabot PRs the job is skipped (the
SonarCloud GitHub App's separate `SonarCloud Code Analysis` check
never posts because no scan runs). The required check is the
workflow job's own `SonarCloud scan` name, not the App's; the
job-level skip on Dependabot still posts as success.

Workflows that are still path-filtered and intentionally NOT in
required: `c-lint.yml`, `openapi-lint.yml`, `swift-lint.yml`. Their
scope is narrow enough that gating them is more ceremony than the
fast feedback is worth; they remain advisory.
