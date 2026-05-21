# L5 system-test harness

Asserted automation around the dogfood QA scripts under `scripts/qa/`.
The driver at `scripts/uat/system-test.sh` SSHs into the SIP-enabled `edr-qa`
VM, optionally installs the candidate PKG and waits for system-extension
activation, runs a scenario's `attack.sh`, then polls the server's REST
API for the expected detections.

This is the L5 layer of the testing pyramid (per `docs/testing-strategy.md`
and `ai/uat/extension-testing.md`): unlike L0..L4 it does not run per PR;
it runs against release candidates and on a schedule via a self-hosted
runner (M11). For per-PR signal on extension wire shapes see L0 unit
tests (M7) and L0 corpus replay (M8).

## Difference vs `scripts/qa/`

| | `scripts/qa/*.sh` | `scripts/uat/system-test.sh` |
|---|---|---|
| Audience | Operator running the dogfood demo | CI / release validation |
| Output | Human-readable per-step summary | Pass/fail per scenario + per rule |
| Exit code | 0 on script completion | 0 = scenario passes, 2 = at least one assertion failed |
| Auth | Each script re-auths | Driver auths once; scenarios inherit |
| PKG install | Manual prereq | Driver handles install + activation wait |
| Relationship | Originals | Wrap and assert around the originals |

`scripts/qa/*.sh` files are NOT deleted or modified by this harness -- the
scenario wrappers SCP and exec the existing scripts, surfacing their exit
codes. A contributor iterating on the dogfood demo edits the qa script;
M9's assertion layer picks the change up automatically.

## Directory layout

    scripts/uat/
      README.md              -- this file
      system-test.sh         -- the driver
      lib/
        common.sh            -- shared SSH + REST + polling helpers
      scenarios/
        attack-runbook/      -- fires every shipped detection rule
          README.md
          attack.sh
          expected.yaml

A blocklist policy-roundtrip scenario used to live here; it has been
dropped because the underlying server endpoint (`/api/policy`) is gone --
the replacement is the per-policy app-control admin surface at
`/api/v1/app-control/*`. A fresh scenario over the new API is tracked
separately.

## Running

Required environment:

    EDR_SERVER_URL=https://edr.local:8088     # no trailing slash
    EDR_SESSION_COOKIE=<paste from devtools>  # see "Auth flow" below
    VM_SSH_TARGET=victor@192.168.64.7         # edr-qa, SIP on. NOT edr-dev.

Optional environment (only consumed by inner `scripts/qa/*.sh` wrappers that
still print these in their per-step summary; the driver itself does not need
them):

    EDR_ADMIN_EMAIL=admin@fleet-edr.local
    EDR_ADMIN_PASSWORD=<paste from server boot log>

### Auth flow

The server has no password-based `POST /api/session` route; login is OIDC
(browser redirect to dex / IdP) or break-glass WebAuthn (passkey, browser-
only). Neither is shell-scriptable. The realistic L5 mechanic is to do ONE
browser login, copy the `edr_session` cookie value from devtools
(Application → Cookies → `edr_session`), export it as `EDR_SESSION_COOKIE`,
and reuse it across many scenario runs until the session expires.

The driver verifies the cookie up front by calling `GET /api/session`. If
that returns 401, the cookie is expired and the driver fails fast — repeat
the browser login.

Run one scenario:

    scripts/uat/system-test.sh attack-runbook

Options:

    --skip-install        Skip PKG install + extension-activation wait.
                          Useful when iterating on a scenario against an
                          already-enrolled VM.
    --pkg-path=PATH       Override the PKG path; default is the most
                          recently built dist/fleet-edr-*.pkg.
    --dry-run             Walk the orchestration shape without actually
                          SSH-ing or curl-ing. Always exits 0 on success;
                          useful for verifying a scenario's expected.yaml
                          parses correctly before driving real infrastructure.

## Why edr-qa and not edr-dev

`edr-qa` (192.168.64.7) runs with SIP enabled + Gatekeeper enabled +
auto-update disabled, all six toggles flipped off so the macOS version
does not drift between snapshot revert and test. That matches what a
pilot customer's MDM-deployed Mac actually looks like -- which is what
L5 must validate against.

`edr-dev` (192.168.64.5) runs with SIP disabled for fast iteration.
Running L5 there would catch nothing extra over L0/L4 and would
contaminate `edr-qa`'s "clean-pre-install" snapshot if we cross-wired
them. The VM environment requirements (SIP enabled, Gatekeeper enabled,
snapshot-restored per run, no Xcode / Homebrew) are spelled out in the
L5 section of `docs/testing-strategy.md`.

## Adding a new scenario

1. Create `scripts/uat/scenarios/<name>/`.
2. Drop in an `attack.sh` (executable). It receives:
   - `UAT_VM_SSH_TARGET` -- ssh target
   - `UAT_HOST_ID` -- the VM's host_id on the server
   - `UAT_SCRIPT_DIR` -- scripts/uat/ absolute path (for sourcing lib/common.sh)
   It should exit 0 on its own assertions passing, non-zero otherwise.
3. Drop in an `expected.yaml`. Schema (indented as YAML; `# comments` are
   tolerated on any line — the driver's awk parser strips inline comments
   before extracting values):

       scenario_id: <name>
       description: <one line for operator logs>
       within_seconds: 120
       # Optional: each rule_id the scenario expects to fire an alert for.
       # Omit the block when the scenario's only assertion is attack.sh exit 0.
       rules:
         - rule_id: my_rule_id
           severity: high
           expect: alert
           description: <operator-facing>

4. Drop in a `README.md` describing what the scenario proves and what it
   does not.
5. Verify with `scripts/uat/system-test.sh <name> --dry-run` -- the driver
   loads the YAML, walks the orchestration, and reports per-rule
   "would-poll-for" lines.

## CI integration

Per-PR: NOT integrated. M9 ships only the harness; M11 wires the
self-hosted GitHub Actions runner on the developer's Mac (label
`macos-self-hosted-edr-qa`) that invokes this driver on a schedule and
on release tags.

Until M11, the harness runs manually via the commands above. The
asserted-scenario shape means a manual run still produces a clear
pass/fail signal suitable for a release-candidate checklist.
