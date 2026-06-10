# Maintenance schedule

A catalogue of recurring codebase-hygiene tasks that Claude (or a human) runs on a cadence. The point is to catch the kinds of decay that compound silently between feature work, where a quick weekly or monthly sweep prevents an eventual multi-day cleanup or, worse, a production incident traced to stale guidance.

## Philosophy

Three rules to keep this from becoming maintenance theatre:

1. **Don't duplicate CI.** Every task here addresses something CI / linters / Dependabot / SonarCloud / arch-go / Scorecard cannot already catch. If a check belongs in CI, file it as a CI gap and move on.
2. **Bias toward verifiable outcomes.** Each task lists a "definition of done" with concrete artefacts (a PR, a deleted line, an updated ADR). Reports without follow-up changes are noise.
3. **Refuse compounded scope.** If a sweep finds a 3-day refactor, file an issue and stop the sweep. Maintenance tasks must finish in their stated time budget, otherwise they get skipped, which is worse than running them shallow.

## What 2025-2026 industry guidance changed

These tasks were chosen with the following deltas in mind, not just generic "review your docs" advice:

- **AI assistant configuration is now part of the codebase.** [`CLAUDE.md`](../../CLAUDE.md) (committed) and the per-maintainer `MEMORY.md`, slash commands, and skills under `~/.claude/` and `.claude/` now drift the same way prose docs always have. (Other tools in the ecosystem use `AGENTS.md`, `.cursor/rules`, etc.; this repo standardises on Claude Code so only [`CLAUDE.md`](../../CLAUDE.md) is committed.) These rules need a dedicated audit cadence because they are invisible to compilers and linters but actively shape every change.
- **Living best-practices audits over one-shot style guides.** Modern codebases (Kubernetes, Sigstore, Falco) treat their best-practices docs as periodically re-evaluated checklists, not write-once prose. The repo already does this in [`docs/best-practices.md`](../best-practices.md); the schedule formalises the refresh cadence so unchecked items don't silently rot.
- **Fitness functions catch architectural drift continuously.** `arch-go.yml` is the structural fitness function; the [`architecture-drift.md`](tasks/architecture-drift.md) task is for the _semantic_ drift that fitness functions can't express (e.g. "context A is reaching into context B's data model conceptually even though the imports are clean").
- **ADRs need supersession, not just creation.** ADRs that are never marked superseded are worse than missing ADRs because they encode decisions that are no longer in force. The [`adr-audit.md`](tasks/adr-audit.md) task explicitly looks for ADRs that have been quietly reversed.
- **Threat models decay with the data plane.** A threat model written before mTLS, before the network extension, before per-context boundaries is a liability, not an asset. The schedule treats it as code, not a one-off artefact.

## What is NOT scheduled here (and why)

These have automation that runs on every PR or every push, so a periodic human-triggered sweep is wasted effort:

| Concern                  | Already handled by                                                          |
| ------------------------ | --------------------------------------------------------------------------- |
| Dependency upgrades      | Dependabot (`.github/dependabot.yml`)                                       |
| Go CVEs                  | `go-vulncheck.yml`                                                          |
| Multi-ecosystem CVEs     | `osv-scanner.yml`                                                           |
| Static security analysis | `codeql.yml`                                                                |
| OSS health posture       | `scorecard.yml`                                                             |
| Workflow security        | `zizmor.yml`                                                                |
| Architecture imports     | `arch-go.yml`                                                               |
| Go nil safety            | `go-nilaway.yml`                                                            |
| Coverage gates           | Codecov + SonarCloud (≥80% on new code)                                     |
| Code formatting / lint   | `lefthook.yml` (pre-commit) + per-language CI lints                         |
| AI review of PRs         | Copilot, CodeRabbit, Gemini, SonarCloud (handled by `/ai-review-fixes-edr`) |

If a finding from a scheduled task could be moved into one of those automated gates, do it. The schedule should shrink over time as automation absorbs more of it.

## Cadence calendar

| Cadence | Tasks |
| --- | --- |
| **Monthly** | [`doc-accuracy-sweep`](tasks/doc-accuracy-sweep.md), [`stale-implementation-references`](tasks/stale-implementation-references.md), [`memory-and-claudemd-audit`](tasks/memory-and-claudemd-audit.md), [`todo-fixme-sweep`](tasks/todo-fixme-sweep.md), [`observability-review`](tasks/observability-review.md) |
| **Quarterly** | [`adr-audit`](tasks/adr-audit.md), [`best-practices-refresh`](tasks/best-practices-refresh.md), [`architecture-drift`](tasks/architecture-drift.md), [`dead-code-sweep`](tasks/dead-code-sweep.md), [`test-suite-health`](tasks/test-suite-health.md), [`claude-config-audit`](tasks/claude-config-audit.md), [`ai-review-bot-config-audit`](tasks/ai-review-bot-config-audit.md), [`threat-model-and-security-refresh`](tasks/threat-model-and-security-refresh.md) |

Suggested anchor: run monthly tasks on the first Monday, quarterly tasks on the first Monday of the quarter (Jan / Apr / Jul / Oct). A "kick the can" of one week is fine; skipping a quarter twice in a row is not.

## How to run

Three options, in order of increasing automation:

1. **Manual.** Open the task file, copy the prompt template into a fresh Claude session, run it on a branch, review the diff, commit. This is the default and the safest. Each task is sized to fit one session.
2. **`/loop` (foreground recurring).** `/loop /<task-name>` if you want to step through several tasks in one sitting.
3. **`/schedule` (cron'd remote agent).** Wire monthly / quarterly tasks to remote routines so they propose PRs without prompting. Only do this for tasks whose definition-of-done can be verified by reading a PR. Do NOT schedule tasks that mutate the threat model, ADRs, or [`CLAUDE.md`](../../CLAUDE.md) autonomously: those decisions need a human in the loop.

## Adding a new task

When you find a new class of decay that bites repeatedly, add a task file. The bar:

- It catches drift that CI cannot express.
- It can be scoped so a single sweep finishes in its stated time budget.
- It produces a verifiable diff (or an explicit "no changes" finding written down with date).

Use any existing task file as a template. Update the cadence calendar above and the task index below.

## Task index

### Documentation hygiene

- [`doc-accuracy-sweep`](tasks/doc-accuracy-sweep.md): prose-vs-code drift across `docs/`, [`README.md`](../../README.md), [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- [`stale-implementation-references`](tasks/stale-implementation-references.md): phase numbers, dead branch names, removed files, broken URLs in committed docs
- [`adr-audit`](tasks/adr-audit.md): ADR freshness, supersession, missing decisions
- [`best-practices-refresh`](tasks/best-practices-refresh.md): industry-delta refresh of [`docs/best-practices.md`](../best-practices.md)

### Codebase health

- [`todo-fixme-sweep`](tasks/todo-fixme-sweep.md): fix, file an issue, or delete; never let TODOs accumulate
- [`dead-code-sweep`](tasks/dead-code-sweep.md): orphan packages, unused exports, dead UI components, abandoned migrations
- [`test-suite-health`](tasks/test-suite-health.md): flaky, skipped, slow, semantically thin
- [`architecture-drift`](tasks/architecture-drift.md): semantic boundary violations beyond what `arch-go` catches

### AI tooling hygiene (new domain)

- [`claude-config-audit`](tasks/claude-config-audit.md): `.claude/settings*.json`, hooks, slash commands, skills
- [`memory-and-claudemd-audit`](tasks/memory-and-claudemd-audit.md): `~/.claude/projects/.../MEMORY.md` + [`CLAUDE.md`](../../CLAUDE.md) accuracy
- [`ai-review-bot-config-audit`](tasks/ai-review-bot-config-audit.md): `.coderabbit.yaml` + future Copilot/Gemini/Qodo configs: path-glob validity, tools roster, pre-merge thresholds, multi-platform glob coverage

### Product / cross-cutting

- [`threat-model-and-security-refresh`](tasks/threat-model-and-security-refresh.md): threat model + security boundaries vs current data plane
- [`observability-review`](tasks/observability-review.md): OTel coverage, dashboard usefulness, alert noise
