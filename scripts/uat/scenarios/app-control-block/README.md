# app-control-block scenario

L5 system/VM coverage for **Application Control active blocking** - the half of
the App Control story that detection scenarios (attack-runbook) do not exercise.

It is the replacement for the removed `e2-policy-roundtrip.sh` blocklist scenario
(`scripts/qa/README.md` "Known gaps"): when the singleton `/api/policy` blocklist
became the per-policy `/api/v1/app-control/*` surface (#289 / #290), the old L5
scenario was deleted and its replacement was "tracked separately". This is it. It
is also the missing half of the #301 acceptance gate ("Application Control still
works", VM-validated on a SIP-on host).

## What it does

It walks every block rule type the AUTH_EXEC decider supports (#210), one probe per
type. Each probe uses a **distinct** non-platform binary whose only matching
identifier is the rule type under test, so the decider's precedence ladder
(`CDHASH > BINARY > CERTIFICATE > SIGNINGID > TEAMID > PATH`) never lets one probe's
rule mask another's. Per probe it: confirms the target runs at baseline, POSTs a
`BLOCK` rule on the seeded Default policy, polls until the snapshot fan-out reaches
the host and the exec is **DENIED** (host-side enforcement), then asserts the
resulting `application_control_block` alert for the exact `rule_id` it created.

Binaries are built on the VM via `go build` (a locally compiled binary lacks Apple's
`is_platform_binary` flag, so the platform carve-out does not exempt it; an
ad-hoc-signed copy of a system `arm64e` binary would instead be killed by AMFI under
SIP). Cleanup deletes every created rule, the work tree, and any temp keychain on exit.

### Rule-type coverage matrix

| Rule type | Mode on a bare edr-qa | How |
|---|---|---|
| `BINARY` | live | block by file SHA-256 |
| `PATH` | live | block by canonical absolute path (server + extension both rewrite `/tmp`→`/private/tmp`) |
| `CDHASH` | live | ad-hoc + Hardened Runtime sign (`CS_RUNTIME` surfaces the cdhash); no Apple ID needed |
| `CERTIFICATE` | fixture | leaf signing-cert SHA-256 |
| `SIGNINGID` | fixture | `<TeamID>:<bundle.id>` |
| `TEAMID` | fixture | 10-char Developer-ID team |

`CERTIFICATE`, `SIGNINGID`, and `TEAMID` are the **signing-derived** types: they only
match a binary that carries a real Apple-issued identity, and that identity must be
**distinct from the EDR's own** (`FDG8Q7N4CC`) - a `CERTIFICATE` rule on the EDR's shared
leaf, or a `TEAMID` rule on its team, would also match the agent + extension. So they're
driven by one externally-signed fixture binary rather than a generated one:

    UAT_ACBLOCK_FIXTURE_BIN   path on the HOST to a Developer-ID-signed binary with a non-EDR identity
    UAT_ACBLOCK_FIXTURE_ARGS  args that make it exec-and-exit-0 cleanly (default: --version)

A small, self-contained, CLI-safe binary already on most dev Macs works well - e.g. the
1Password CLI `op` (team `2BUA8C4S2C`). The scenario derives the binary's team / signing
id / leaf-cert SHA-256 with **read-only** `codesign` on the host (it never executes the
fixture there), copies the binary to the VM's `/tmp` (a file, **not** an install -
removed on cleanup), execs it only on the VM, and refuses any fixture whose team is the
EDR's own. The three share one binary, so each is tested in isolation
(post → deny → remove → allow-again) since the precedence ladder would otherwise let a
lingering higher-precedence rule mask the next. Unset → all three skip with a clear
message; all three are covered at L0 by `AuthExecDeciderPhaseBTests`.

## Prerequisites

A working `go` toolchain on the VM (found on `PATH` or under `/usr/local/go/bin`),
used to compile the non-platform block targets. This matches the attack-runbook
scenario, which also `go build`s its launchd dropper. If `go` is absent the
scenario fails fast with a clear message rather than a cryptic build error.

## Run

    task uat:l5 -- app-control-block --skip-install   # against an enrolled VM
    task uat:l5 -- app-control-block                  # full install + scenario

Same required env as attack-runbook (see `../../README.md`): `EDR_SERVER_URL`,
`EDR_SESSION_COOKIE`, `VM_SSH_TARGET`, and `UAT_INSECURE=1` for the local dev cert.

To also exercise the signing-derived types, add `UAT_ACBLOCK_FIXTURE_BIN` (see the matrix
above), e.g.:

    UAT_ACBLOCK_FIXTURE_BIN=/opt/homebrew/bin/op task uat:l5 -- app-control-block --skip-install
