# AI review-bot config audit

**Cadence:** quarterly
**Time budget:** 30 min
**Trigger mode:** manual

## Why this matters

`.coderabbit.yaml` (and any future bot configs — Copilot custom instructions,
Gemini Code Assist style guides, Qodo policy files) sit in the same gap as
`CLAUDE.md`: they actively shape every PR review but no compiler or CI gate
catches drift. A path glob that no longer matches the tree, a tool key the
vendor renamed, a docstring threshold that made sense before test/e2e/
existed — each silently degrades review quality. Nobody notices until a
real finding gets buried under noise or a regression slips through because
the path_instruction for that directory was pointing at a dead path.

This task is the periodic re-grounding. It is deliberately small (30 min)
because most quarters the answer is "no change needed" and the value is in
*verifying* that, not in finding work.

## Scope

Primary: `.coderabbit.yaml`.

Secondary (when they appear): any future PR-review-bot config files
committed to the repo — `.github/copilot-instructions.md`,
`.gemini/styleguide.md`, `.qodo/config.yaml`, etc. Treat this audit as the
catch-all for the class.

Out of scope: per-maintainer Claude config (covered by `claude-config-audit`),
CodeRabbit's organization-level / dashboard-only settings (those drift
separately and the bot's own UI surfaces them).

## Steps

### 1. Schema currency

Skim CodeRabbit's [configuration reference](https://docs.coderabbit.ai/reference/configuration)
and [YAML template](https://docs.coderabbit.ai/reference/yaml-template).
For each top-level key in the repo's `.coderabbit.yaml`, confirm:

- The key still exists (no deprecation rename).
- The value type still matches (especially enum values for `profile`,
  `mode`, `level`).
- No new top-level key was added that this repo would obviously benefit
  from (e.g. an audit-trail option, a security-tuning preset).

Note any deprecation warnings in CodeRabbit's most recent walkthrough on
a merged PR — the bot itself flags deprecated keys.

### 2. Path glob validity

For every `path_filters` entry and every `path_instructions[*].path` glob,
verify at least one file in the current tree matches. A glob with zero
matches is dead config: either the directory moved, the project never had
that surface, or a refactor renamed it.

Quick check: `git ls-files | grep -E '<glob-as-regex>'` for spot-checking.
For matrix-shape globs like `{audit,sessions,authz,oidc,seed,rbac}`, walk
each alternative; a single missing alt isn't a failure, but mark the
glob for trim if more than half are gone.

### 3. Tools list

CodeRabbit's tools roster grows ~quarterly. For each tool listed in
`reviews.tools` of the repo config:

- Is the key still recognised? (rename check)
- Is its CI counterpart still running? An enabled-in-CodeRabbit tool
  whose CI mirror was deleted should flip to `enabled: false` (or vice
  versa).
- For disabled tools listed by name: is the disable still load-bearing?
  When the CI job that justified the disable goes away, remove the
  override and let the default fire.

Then look at the FULL tools list in the schema reference for anything
*new* since the last audit. Apply the security-first rule:

- New SAST / secrets / SBOM / IaC-misconfig tool → consider enabling if
  not already in CI.
- New language-specific tool (Ruby, Kotlin, etc.) → skip unless that
  language landed in the repo.

### 4. Pre-merge thresholds

Pull the most recent ~5 PRs and check whether the pre-merge checks
(`docstrings`, `title`, `description`) fired with the right cadence:

- If the docstring threshold is silently 100%-passing on every PR, it's
  probably too low — bump.
- If it's failing on every PR, it's too high or the rule is wrong for
  the file mix — adjust threshold OR add path filters to the docstring
  surface.
- Same for title / description rules.

The goal: ~10-20% of PRs trip a warning, not 0% and not 100%.

### 5. Tone + path_instructions alignment

For each `path_instructions` block, read the latest CodeRabbit walkthrough
that touched that path. Did the bot's findings reflect the threat-model
language in the instruction? If the instruction says "audit append-only
invariant" but the bot is still flagging style nits in that dir, the
instruction needs to be either tighter or more specific.

Don't grow the instructions during this sweep — the file should NOT
balloon. If something's missing, file an issue and stop. Tighten or
remove during this pass; expand on a deliberate future PR.

### 6. Multi-platform sanity check

This product is extending from macOS to Windows + Linux. For every
`path_instructions` glob:

- Does the glob match BOTH macOS code AND the eventual Windows / Linux
  equivalent? (`agent/**` matches per-OS subtrees; `agent/internal/macos/**`
  would not.)
- Does the instruction text use OS-agnostic language where the threat is
  cross-platform, and OS-specific language only when it's genuinely
  OS-specific (ESF, ALPC, eBPF)?

A new platform's code landing should not require rewriting `.coderabbit.yaml`
from scratch.

### 7. Commit + log

If anything changed: open a PR titled `coderabbit: config audit YYYY-Q\d`,
listing each change with a one-line rationale.

Even if nothing changed: append an entry to `docs/maintenance/log.md`
recording `done` with `no findings`. The empty entries are how we know
the cadence is being honoured.

## Output

Either a PR (when changes land) or a log entry (when no changes).

## Prompt template

```
Run the AI review-bot config audit defined in
docs/maintenance/tasks/ai-review-bot-config-audit.md.

Steps:
  1. Check CodeRabbit schema currency vs https://docs.coderabbit.ai/reference/configuration
     and https://docs.coderabbit.ai/reference/yaml-template — flag any deprecated keys
     used in the repo's .coderabbit.yaml.
  2. For every path_filters + path_instructions glob, verify at least one
     file matches the current tree (use `git ls-files`).
  3. Review the tools list: confirm disables still match CI's gates, and
     scan the upstream schema for new security-relevant tools added since
     the last audit.
  4. Sanity-check pre_merge_checks thresholds against the last ~5 PRs'
     warnings (target ~10-20% trip rate).
  5. Eyeball path_instructions against the last walkthroughs on those
     paths — are the instructions actually steering the bot?
  6. Verify multi-platform glob patterns still work for an EDR extending
     beyond macOS.

If changes are needed: open a PR `coderabbit: config audit YYYY-Q\d` with
each change one-line-justified. If nothing changed: append a `done | no
findings` entry to docs/maintenance/log.md.

Time budget 30 min. Stop and file an issue if you find a 1+ hour fix.
```

## Definition of done

- [ ] Every glob in `.coderabbit.yaml` matches ≥ 1 file in the current tree
      (or has been trimmed).
- [ ] No deprecated CodeRabbit keys are used.
- [ ] Tools list disables still align with active CI workflows.
- [ ] Pre-merge thresholds spot-checked against recent PR walkthroughs.
- [ ] Multi-platform glob coverage verified.
- [ ] PR opened OR `no findings` log entry appended.
