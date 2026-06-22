# Version-agnostic + destination-aware suppression for suspicious_exec

## Why

The `suspicious_exec` rule (non-shell -> shell -> temp-exec OR outbound network connection) has exactly one suppression knob: `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` (`AllowedNonShellParents`), which matches the non-shell parent path verbatim with a map lookup. That is too brittle and too coarse to quiet legitimate developer tooling without blinding the rule.

Two concrete problems, grounded in 108 open benign network-arm alerts on the pilot dev host (issue #391):

1. **Path-exact, version-pinned matching.** The real parent paths are version-stamped (`.../claude/versions/2.1.175`, `.../mise/installs/lefthook/1.8.0/lefthook_1.8.0_MacOS_arm64`, `/opt/homebrew/Cellar/git/2.42.1/bin/git`). Every tool upgrade silently breaks the suppression because there is no prefix/glob support. 79 of the 108 alerts are Claude Code, 26 lefthook, 2 git, 1 GoLand: all version-churning developer binaries.

2. **DNS noise.** 56 of the 108 are outbound to the host's own resolver on `:53` (Tailscale MagicDNS at `100.100.100.100`). A name-resolution lookup to the host's local resolver is not a meaningful "outbound network connection" for this rule: the meaningful signal is the connection to the resolved address that follows, which the network arm still sees.

## What changes

- **Version-agnostic parent matching.** `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` entries MAY contain `*` wildcards. A `*` matches any run of characters including the path separator, so a single `*/claude/versions/*` or `*/lefthook_*` survives version churn and directory-depth differences. An entry with no `*` keeps exact-match semantics, so existing operator configs (`/usr/libexec/sshd-session`) are unaffected. Matching is the only change; the env var, its CSV shape, and the both-arms suppression semantics are unchanged.

- **Local-resolver DNS de-noising (always on, no knob).** An outbound `network_connect` to port 53 whose `remote_address` parses as a local-resolver-class IP (loopback, RFC1918 private, IPv4 link-local, the CGNAT `100.64.0.0/10` range that Tailscale MagicDNS uses, or IPv6 ULA / link-local / loopback) does NOT count as a triggering outbound connection for the network arm. DNS to a public resolver IP on `:53` still fires. This is a destination-CLASS filter ("the host's own resolver"), not destination-IP/ASN allowlisting, and it does not touch the temp-exec arm.

## Scoped out (documented, not closed)

The full Falcon/Defender/SentinelOne-style IOA-exclusion tuple (parent signer + command-line substring + resolved destination class) that would waive trusted dev-tool -> registry traffic WITHOUT blinding the temp-exec arm is deliberately out of scope: it needs a richer config representation than the flat CSV env var. The documented limitation that allowlisting a parent silences BOTH arms therefore persists for glob entries exactly as it does for literal entries today. DNS de-noising is the one destination-aware win that lands here because it is arm-scoped and needs no per-deployment config.

Code-signing / team-ID based parent matching (the issue's alternative to globs) is also out of scope: the noisy parents on the evidence host are mostly ad-hoc-signed or unsigned developer binaries (lefthook installed via mise, Homebrew git) with no stable team ID, so a team-ID predicate would not cover them. Globs are the primitive that fits the evidence.

## Impact

- Affected specs: `server-detection-rules-engine` (two added requirements: version-agnostic parent allowlist matching, local-resolver DNS suppression).
- Affected code: `server/rules/internal/catalog/suspicious_exec.go` (glob matcher + `parentAllowed` + `evalNetwork` DNS gate + `Doc()`), `server/config/config.go` (field docstring only; no parsing change), `server/rules/internal/catalog/suspicious_exec_test.go` (new tests).
- No wire-format, schema, migration, or agent/extension change. Server-only, no VM-gated telemetry change.
- Operator-facing: the `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` documentation in `docs/detection-rules.md` regenerates to describe glob support.
