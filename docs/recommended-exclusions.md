# Recommended detection exclusions

Detection rules fire on behavioral shapes, not on reputation, so a handful of legitimate tools on a real endpoint will match a rule's shape and raise a benign alert. This page lists a small, universal set of exclusions we recommend seeding, then explains how to handle the environment-specific tooling exclusions you add yourself. Each entry is a true positive (the activity really happened) that is not malicious in context, so the right response is a scoped exclusion rather than muting the rule.

Add these on the detection-config exclusions surface in the console (sign in as an admin). Each exclusion needs a `reason`; the value is audited. Exclusions are global today (host-group scoping is not yet honored). Service accounts cannot write exclusions yet (see [getvictor/fleet-edr#518](https://github.com/getvictor/fleet-edr/issues/518)), so add these as a human admin in the UI, not through an automated token.

## How matching works

An exclusion is `(rule_id, match_type, value)`. The value is matched per the rule's match type:

- `parent_path_glob`: matches a chain's non-shell parent path. `*` matches any run of characters including `/`. A pattern with no `*` is an exact match.
- `team_id`: matches an Apple Developer team ID exactly.
- `path_glob`: matches an absolute filesystem path with the same glob semantics as `parent_path_glob`.

Which rule consumes which match type is fixed by the rule:

| Rule                            | Match type used    |
| ------------------------------- | ------------------ |
| `suspicious_exec`               | `parent_path_glob` |
| `privilege_launchd_plist_write` | `team_id`          |
| `persistence_launchagent`       | `path_glob`        |
| `sudoers_tamper`                | `path_glob`        |

## Caveats before you add an exclusion

- A `suspicious_exec` `parent_path_glob` exclusion silences BOTH arms of the rule for that parent (the temp-path exec arm and the outbound-network arm). You are trusting everything that parent does, not just the one connection you saw.
- Never start a path glob with `*`, and minimize interior wildcards. Because `*` matches any run of characters including `/`, a leading-wildcard pattern like `*/claude/versions/*` matches that fragment anywhere on disk, so an attacker who can write to `/tmp` creates `/tmp/claude/versions/payload` and runs it to land inside the exclusion. Anchor to the full absolute install path instead; the longer the literal prefix, the less an attacker can spoof.
- A path exclusion is only as trustworthy as the write permissions on the directory it points at. Anchor to a root-owned install root (`/usr/bin`, `/usr/local/bin`, `/opt/homebrew/...`) that an unprivileged attacker cannot write to. A path under a user home or any world-writable location can be recreated by the attacker, so it carries real residual risk even when anchored. This is sharper on multi-user hosts: a home-anchored glob with a wildcarded user segment (`/Users/*/...`) matches every user's home, so any local user, not just the intended one, can plant a binary at the excluded path and evade the rule.
- For `team_id`, notarization is deliberately not a trust signal (Apple has notarized malware, and it is not checkable network-free on the event thread). The team-ID allowlist is the operator's explicit trust decision. Confirm the exact team before allowlisting it: `codesign -dv <binary>` prints `TeamIdentifier`.

## Workstations vs servers

Some of these are workstation-only noise. `suspicious_exec` is tuned for non-interactive endpoints, where a non-shell process spawning a shell that then reaches the network is genuinely suspicious. On an interactive developer workstation that exact shape is normal: opening a terminal (`/usr/bin/login` spawns your login shell) and having the shell startup or your first command touch the network looks identical to the dropper the rule hunts. Until we can differentiate host classes and apply a workstation profile, the `/usr/bin/login` exclusion below suppresses that baseline noise on workstations. Do NOT apply the `/usr/bin/login` exclusion to servers: on a server, a login shell reaching the network is a signal worth keeping.

## Recommended exclusions

| Rule | Match type | Value | Applies to | Reason |
| --- | --- | --- | --- | --- |
| `suspicious_exec` | `parent_path_glob` | `/usr/bin/login` | Workstations only | Interactive terminal logins spawn a shell that routinely reaches the network. Interim until host-class profiles exist. |
| `privilege_launchd_plist_write` | `team_id` | `FDG8Q7N4CC` | All hosts | The EDR agent's own LaunchDaemon registration. Signed by the EDR vendor team; allowlist so the agent does not flag its own persistence. |

The `FDG8Q7N4CC` entry is the only one keyed on a team ID because `privilege_launchd_plist_write` is the only team-ID-gated rule. It should ideally be seeded at install time so a freshly deployed agent does not alert on its own daemon registration. Verify the team on the installed binary with `codesign -dv /usr/local/bin/fleet-edr-agent` before relying on it.

## Environment-specific exclusions

The table above is deliberately minimal because it is the only set that applies to every deployment. Most of the benign `suspicious_exec` noise you actually see comes from tooling specific to your fleet, so those exclusions are yours to add, not blanket recommendations: add one only for a tool actually present in your environment. Common offenders shell out and then reach the network, which is exactly the rule's shape: infrastructure-as-code tools, AI coding assistants, CI runners, and package managers. Exclude each with a `parent_path_glob` anchored to the tool's full absolute install path, never a leading-wildcard fragment (see the caveats above for why `*/tool/...` is attacker-spoofable). For example, only if your fleet runs them:

- Terraform installed via Homebrew on Apple Silicon: `/opt/homebrew/Cellar/terraform/*/bin/terraform`. Anchored under the root-owned Homebrew prefix; the single `*` spans only the version directory.
- Claude Code: `/Users/*/.local/share/claude/versions/*`. This one lives under a user home, which an attacker can also write to, so it carries more residual risk than a root-owned path even when anchored. Add it only on workstations where the noise is real, and never on servers.

Confirm the real install path on one of your own hosts (`which <tool>`, then resolve symlinks) before adding the glob, and anchor to that exact location.
