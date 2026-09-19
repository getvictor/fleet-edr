# Recommended detection exclusions

Detection rules fire on behavioral shapes, not on reputation, so a handful of legitimate tools on a real endpoint will match a rule's shape and raise a benign alert. This page lists a small, universal set of exclusions we recommend seeding, then explains how to handle the environment-specific tooling exclusions you add yourself. Each entry is a true positive (the activity really happened) that is not malicious in context, so the right response is a scoped exclusion rather than muting the rule.

Add these on the detection-config exclusions surface in the console, or through `POST /api/v1/detection-config/exclusions` as a user or service account whose role grants `detection_config.write` (the admin role does). Each exclusion needs a `reason`, and the create is audited. Exclusions are global today (host-group scoping is not yet honored).

## How matching works

An exclusion is `(rule_id, match_type, value)`, with an optional expiry. The value is matched per the rule's match type:

- `parent_path_glob`: matches a chain's non-shell parent path. `*` matches any run of characters including `/`, and it is the only wildcard. A pattern with no `*` is an exact match. Matching is case-sensitive.
- `team_id`: matches an Apple Developer team ID exactly (the `TeamIdentifier` field of the code signature).
- `signing_id`: matches a code-signing identifier QUALIFIED by who signed it, written `<TEAMID>:<identifier>` (for example `Q6L2SF6YDW:com.anthropic.claude-code`) or `platform:<identifier>` for a binary Apple ships. Both parts must match, so an ad-hoc binary claiming a vendor's identifier is not covered. `codesign -dv <binary>` prints both fields. A bare identifier is refused.
- `cdhash`: matches a binary's code-directory hash exactly (40 lowercase hex characters), pinning one exact build. The agent reports a cdhash only for binaries built with Hardened Runtime, so it cannot match an ad-hoc signed binary such as most Homebrew formulae.
- `path_glob`: matches an absolute filesystem path with the same glob semantics as `parent_path_glob`.

Which rule consumes which match type is fixed by the rule, and the console offers only the match types the selected rule actually consults. Creating an exclusion for a `(rule_id, match_type)` pair the rule does not consult, or for a rule that does not exist, is rejected by the API, so a stored exclusion cannot silently do nothing:

| Rule | Match types used | Matched against |
| --- | --- | --- |
| `suspicious_exec` | `parent_path_glob`, `team_id`, `signing_id`, `cdhash` | The chain's non-shell parent |
| `shell_network_connect` | `parent_path_glob`, `team_id`, `signing_id`, `cdhash` | The chain's non-shell parent |
| `privilege_launchd_plist_write` | `team_id` | The registered daemon's executable |
| `persistence_launchagent` | `path_glob` | The plist path as typed on the launchctl command |
| `sudoers_tamper` | `path_glob` | The process that wrote the sudoers file |
| `sudoers_destroyed` | `path_glob` | The process that removed or replaced the file |

Exclusions are keyed by rule id. `suspicious_exec` and `shell_network_connect` share the same parent-matching logic but not their exclusions, so silencing a parent on both shapes takes one exclusion per rule.

A matched exclusion suppresses the finding before an alert is created, and nothing records that it did. Treat every exclusion as a standing blind spot you cannot audit after the fact, and give environment-specific ones an expiry so they come back up for review.

## Caveats before you add an exclusion

- **Prefer `team_id` for any Developer-ID signed tool.** On Apple Silicon the kernel refuses to run a binary whose signature does not validate, so a planted binary cannot carry a real vendor's team ID. It also survives version updates. Confirm the exact team before allowlisting it: `codesign -dv <binary>` prints `TeamIdentifier`.
- **Use `signing_id` to narrow a team, not to stand in for one.** The value carries the team (`Q6L2SF6YDW:com.anthropic.claude-code`), so an ad-hoc signature claiming that identifier is not covered by it: `codesign -s - -i com.anthropic.claude-code ./payload` produces a binary with no team, which matches nothing. Reach for it when a vendor ships several tools and you want one of them rather than all of them. A bare identifier is refused by the API, because it would be whatever the signer typed.
- **An exclusion trusts everything the parent can be made to run, not just the activity you saw.** An attacker does not need to plant anything to use an excluded parent; invoking the real binary is enough. Never exclude a script interpreter (`python`, `ruby`, `node`, `perl`, `osascript`): `ruby -e 'system("curl ...")'` launders any shell through it. Tools that run commands from their own configuration carry the same risk: `git` (aliases, hooks and `core.sshCommand`), git hook runners such as lefthook and husky, terminal multiplexers, IDEs, and AI coding assistants. Exclude those only where their noise outweighs that blind spot, and prefer an expiry.
- **Never start a path glob with `*`, and minimize interior wildcards.** Because `*` matches any run of characters including `/`, a leading-wildcard pattern like `*/claude/versions/*` matches that fragment anywhere on disk, so an attacker who can write to `/tmp` creates `/tmp/claude/versions/payload` and runs it to land inside the exclusion. A trailing `*` has the same problem inside a directory: `/Users/alice/.local/share/mise/installs/lefthook/*` matches any file an attacker drops anywhere under that tree. Anchor to the full absolute path of the binary itself.
- **A path exclusion is only as trustworthy as the write permissions on the directory it points at.** With System Integrity Protection on, system paths (`/usr/bin`, `/usr/libexec`, `/bin`) cannot be written even by root. Homebrew is not in that class: its installer makes `/opt/homebrew` (Apple Silicon) and its directories under `/usr/local` (Intel) owned by the installing user, so any process running as that user can place a binary at an excluded Homebrew path. The same holds for anything under a user home. Check ownership with `stat -f '%Su' <dir>` before trusting a path. On multi-user hosts a wildcarded user segment (`/Users/*/...`) is worse, because it lets every local user plant a binary at the excluded path.
- **For `team_id`, notarization is deliberately not a trust signal** (Apple has notarized malware, and it is not checkable network-free on the event thread). The team-ID allowlist is the operator's explicit trust decision, and a vendor's team ID covers every product that vendor signs.
- **Write a reason someone else can audit.** Name the tool, how it is signed, the alert that prompted the exclusion, and why the activity is benign. "git" is not a reason.

## Exclusions to avoid

- `/usr/libexec/sshd-session` as a parent on a workstation. It silences every command run over SSH, which is exactly what an attacker with a stolen key or password runs. Where routine SSH administration makes it necessary on a server, set an expiry.
- Any script interpreter as a parent, by path or by signature (see the caveats).
- A glob that ends in `*` inside a user-writable directory, or that starts with `*`.
- A `signing_id` exclusion whose team half names a team you have not confirmed with `codesign -dv`.

## Workstations vs servers

Some of these are workstation-only noise. The shell chain rules are tuned for non-interactive endpoints, where a non-shell process spawning a shell that then reaches the network is genuinely suspicious. On an interactive developer workstation that exact shape is normal: opening a terminal (`/usr/bin/login` spawns your login shell) and having the shell startup or your first command touch the network looks identical to the dropper the rule hunts. Until we can differentiate host classes and apply a workstation profile, the `/usr/bin/login` exclusion below suppresses that baseline noise on workstations.

Know what it costs. The 30-second window starts when the login shell starts, so in practice this exclusion silences what happens in the first 30 seconds of each terminal session: your shell startup files (`.zshrc`, `.zprofile`) and anything typed immediately. Shell startup files are also where shell-profile persistence (MITRE T1546.004) runs. Do NOT apply the `/usr/bin/login` exclusion to servers: on a server, a login shell reaching the network is a signal worth keeping.

## Recommended exclusions

| Rule | Match type | Value | Applies to | Reason |
| --- | --- | --- | --- | --- |
| `shell_network_connect` | `parent_path_glob` | `/usr/bin/login` | Workstations only | Interactive terminal logins spawn a shell that routinely reaches the network. Interim until host-class profiles exist. |
| `privilege_launchd_plist_write` | `team_id` | `FDG8Q7N4CC` | All hosts | The EDR agent's own LaunchDaemon registration. Signed by the EDR vendor team; allowlist so the agent does not flag its own persistence. |

Do not add the `/usr/bin/login` exclusion to `suspicious_exec`: there it only silences temp-directory executions during shell startup, which is the shell-profile persistence case above.

The `FDG8Q7N4CC` entry is the only one keyed on a team ID because `privilege_launchd_plist_write` accepts only team IDs. It should ideally be seeded at install time so a freshly deployed agent does not alert on its own daemon registration. Verify the team on the installed binary with `codesign -dv /usr/local/bin/fleet-edr-agent` before relying on it.

## Environment-specific exclusions

The table above is deliberately minimal because it is the only set that applies to every deployment. Most of the benign shell chain noise you actually see comes from tooling specific to your fleet, so those exclusions are yours to add, not blanket recommendations: add one only for a tool actually present in your environment. Common offenders shell out and then reach the network, which is exactly the rule's shape: infrastructure-as-code tools, AI coding assistants, CI runners, and package managers. For a Developer-ID signed tool, exclude it by its `team_id`. Fall back to a `parent_path_glob` anchored to the tool's full absolute binary path only for an unsigned or ad-hoc signed tool, give it an expiry, and never use a leading-wildcard fragment. For example, only if your fleet runs them:

- Claude Code (signed by Anthropic): `team_id` `Q6L2SF6YDW`. The signature holds across version updates and a planted binary cannot carry it, so it is preferred over a path glob such as `/Users/*/.local/share/claude/versions/*`, which lives under a user home an attacker can write to. Claude Code runs arbitrary shell commands by design, so this exclusion also hides a prompt-injected command that fetches or runs a payload. Confirm the team on your own host with `codesign -dv $(which claude)` before allowlisting it.
- Terraform from HashiCorp's own Homebrew tap or release zip (signed by HashiCorp): `team_id` `D38WU7D763`. It covers every HashiCorp binary, and Terraform's `local-exec` provisioners and `external` data sources run arbitrary commands. A Terraform built from source (for example an older `homebrew-core` formula) is ad-hoc signed and has no team ID; run `codesign -dv $(which terraform)` to see which you have.
- Git installed via Homebrew on Apple Silicon (ad-hoc signed, no team ID): `parent_path_glob` `/opt/homebrew/Cellar/git/*/bin/git`, with an expiry. `/opt/homebrew` is owned by the installing user, so this carries the residual risks in the caveats above.

Confirm the signing identity (`codesign -dv <binary>`) or the real binary path on one of your own hosts before adding an exclusion, and anchor to that exact value. The real path is the one the alert shows as the parent: a version manager may run a differently named binary than the command you type (mise runs lefthook as `lefthook_<version>_MacOS_arm64`, for example).
