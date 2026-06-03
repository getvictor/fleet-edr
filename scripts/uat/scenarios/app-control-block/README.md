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
| `CERTIFICATE` | gated | needs a fixture whose leaf cert SHA-256 differs from the EDR's own Developer ID leaf (a rule on the shared leaf would also match the agent). `codesign` only signs with a *trusted* identity, so a self-signed leaf would require mutating the VM's system trust store - not done on a release VM. Set `UAT_ACBLOCK_CERT_BIN` + `UAT_ACBLOCK_CERT_SHA256`. L0 cover: `AuthExecDeciderPhaseBTests` |
| `SIGNINGID` | gated | needs a Developer-ID-signed fixture (`team_id` is Apple-issued; a self-signed cert yields none). Set `UAT_ACBLOCK_SIGNINGID_BIN` + `UAT_ACBLOCK_SIGNINGID_ID`. L0 cover: `AuthExecDeciderPhaseBTests` |
| `TEAMID` | gated (unsafe by default) | the only Developer-ID team on this host is the EDR's own (`FDG8Q7N4CC`); a `TEAMID` block on it would also deny the agent. Needs a **distinct-team** fixture (`UAT_ACBLOCK_TEAMID_BIN` + `UAT_ACBLOCK_TEAMID_ID`). L0 cover: `AuthExecDeciderPhaseBTests` |

`CERTIFICATE`, `SIGNINGID`, and `TEAMID` are gated because the bare QA VM has no signing
material that is both usable by `codesign` and distinct from the EDR's own identity;
all three are covered at L0 by the extension decider unit tests.

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
