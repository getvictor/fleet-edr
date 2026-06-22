# Tasks

## Server

- [ ] `server/rules/internal/catalog/suspicious_exec.go`: add a small, dependency-free `globMatch(pattern, name)` helper where `*` matches any run of characters (including `/`) and every other byte is literal. A pattern with no `*` is an exact comparison.
- [ ] `parentAllowed`: match `parent.Path` against each allowlist entry: exact-membership fast path, then glob-match for entries containing `*`. Nil parent never matches (unchanged).
- [ ] `evalNetwork`: before walking ancestry, skip outbound `network_connect` events whose `remote_port == 53` and whose `remote_address` parses as a local-resolver-class IP (loopback / RFC1918 / IPv4 link-local / CGNAT `100.64.0.0/10` / IPv6 ULA / IPv6 link-local). Add `isLocalResolverDest` + `isLocalResolverIP` helpers.
- [ ] `Doc()`: update the `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` knob description (glob support), add a FalsePositives note for the local-resolver DNS de-noising, and keep the both-arms Limitation; add a Limitation that DNS to a public resolver still fires.
- [ ] `server/config/config.go`: update the `SuspiciousExecParentAllowlist` field docstring to mention glob support (no parsing change).

## Tests

- [ ] Table-driven `globMatch` unit test: exact match, leading/trailing/embedded `*`, `*` crossing `/`, the three evidence patterns (`*/claude/versions/*`, `*/lefthook_*`, `/opt/homebrew/Cellar/git/*/bin/git`), and non-matches.
- [ ] Glob suppression test: a version-stamped parent (`.../claude/versions/2.1.178/claude`) is suppressed by `*/claude/versions/*`; a literal entry still matches exactly (backward compat).
- [ ] DNS de-noising test: outbound to `100.100.100.100:53` from a shell-spawned process does NOT fire; outbound to a public resolver (`8.8.8.8:53`) still fires; the existing public-IP `:443` test still fires.
- [ ] Spectrace markers (`spec:`) on the new tests for the two added scenarios.

## Gates

- [ ] `go test ./server/rules/internal/catalog/...`
- [ ] `task lint:go`, `task lint:dashes`
- [ ] `tools/spectrace check --strict`
- [ ] `openspec validate suspicious-exec-suppression --strict`
- [ ] Regenerate detection-rule docs (`tools/gen-rule-docs`) so `docs/detection-rules.md` reflects the new knob wording.

## Manual QA

- [ ] dev:server + edr-dev VM: drive a benign dev-tool chain and a DNS-to-local-resolver from a shell; confirm no alert. Drive a `/tmp` payload and a public-resolver lookup; confirm the rule still fires.
- [ ] SigNoz MCP: confirm the detection pipeline traces/metrics reflect the suppression (no new `suspicious_exec` alert spans for the benign chains).

## Archive

- [ ] Archive at release (`openspec archive suspicious-exec-suppression`), not per-merge.
