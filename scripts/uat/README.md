# L5 system-test harness

Asserted automation around the dogfood QA scripts under `scripts/qa/`. The driver at `scripts/uat/system-test.sh` SSHs into the SIP-enabled `edr-qa` VM, optionally installs the candidate PKG and waits for system-extension activation, runs a scenario's `attack.sh`, then polls the server's REST API for the expected detections.

This is the L5 layer of the testing pyramid (per [`testing-strategy.md`](../../docs/testing-strategy.md)): unlike L0..L4 it does not run per PR; it runs against release candidates and on the developer's own machine against a SIP-on VM. For per-PR signal on extension wire shapes see L0 unit tests (M7) and L0 corpus replay (M8). Running L5 from a dedicated self-hosted GitHub Actions runner (so the cron lane and release tags fire automatically) is tracked as a follow-up; for now the harness runs locally only.

## Difference vs `scripts/qa/`

|              | `scripts/qa/*.sh`                 | `scripts/uat/system-test.sh`                           |
| ------------ | --------------------------------- | ------------------------------------------------------ |
| Audience     | Operator running the dogfood demo | CI / release validation                                |
| Output       | Human-readable per-step summary   | Pass/fail per scenario + per rule                      |
| Exit code    | 0 on script completion            | 0 = scenario passes, 2 = at least one assertion failed |
| Auth         | Each script re-auths              | Driver auths once; scenarios inherit                   |
| PKG install  | Manual prereq                     | Driver handles install + activation wait               |
| Relationship | Originals                         | Wrap and assert around the originals                   |

`scripts/qa/*.sh` files are NOT deleted or modified by this harness: the scenario wrappers SCP and exec the existing scripts, surfacing their exit codes. A contributor iterating on the dogfood demo edits the qa script; M9's assertion layer picks the change up automatically.

## Directory layout

    scripts/uat/
      README.md              -- this file
      system-test.sh         -- the driver
      lib/
        common.sh            -- shared SSH + REST + polling helpers
      scenarios/
        app-control-block/   -- App Control active blocking (deny + alert)
          README.md
          attack.sh
          expected.yaml
        attack-runbook/      -- fires every shipped detection rule
          README.md
          attack.sh
          expected.yaml

A blocklist policy-roundtrip scenario used to live here; it was dropped when the `/api/policy` endpoint gave way to the per-policy app-control admin surface at `/api/v1/app-control/*`. Its replacement is the `app-control-block` scenario below, which posts a BINARY BLOCK rule over the new API, confirms the extension denies the matching exec on the VM, and asserts the `application_control_block` alert: L5 coverage for Application Control active blocking.

## Quick start (local execution)

One-time per session:

1. Sign in to the EDR admin UI in a browser (break-glass or OIDC).
2. Devtools -> Application -> Cookies -> copy the `edr_session` value.
3. Export the three env vars below.

Then iterate via the Taskfile target:

    task uat:l5 -- attack-runbook --dry-run        # orchestration smoke, ~1s
    task uat:l5 -- attack-runbook --skip-install   # already-enrolled VM, ~2 min
    task uat:l5 -- attack-runbook                  # full install + scenario, ~5 min

Or call the driver directly (the task target is a thin pass-through):

    scripts/uat/system-test.sh attack-runbook --skip-install

## VM prerequisites

Beyond the SIP / Gatekeeper posture described under "Why edr-qa and not edr-dev", the runbook's `privilege_launchd_plist_write` step needs passwordless sudo for the dropper it compiles. Without it the step is skipped and the driver reports the scenario as INCOMPLETE rather than certifying a rule it never exercised.

The dropper is built at a fresh path on every run, because BTM keys launch-item identity on the executable path and a fixed path would fire the rule only on the host's first ever run. So the sudoers entry needs a glob:

    victor ALL=(ALL) NOPASSWD: /private/tmp/edr-attack-runbook/synthetic_dropper_*, /tmp/edr-attack-runbook/synthetic_dropper_*

Both prefixes are required, not one. macOS resolves `/tmp` to `/private/tmp`, and a sudoers `*` does not span `/`, so a single-prefix rule looks correct and silently matches nothing.

Install it as `/etc/sudoers.d/edr-uat-dropper`, mode 0440 root:wheel, and validate with `visudo -c -f /etc/sudoers.d/edr-uat-dropper` before it goes live. The filename must contain no `.`: sudo silently ignores any file in `sudoers.d` whose name has one.

This is recorded here rather than only on the VM because it has been lost once already, when `edr-qa` was reprovisioned after it was first applied for v0.1.1-rc.13.

## Exit codes

| Code | Meaning                                                                                                            |
| ---- | ------------------------------------------------------------------------------------------------------------------ |
| 0    | PASS. Every expected rule was exercised and alerted.                                                               |
| 1    | Usage or setup error: bad scenario, missing env, missing `expected.yaml`.                                          |
| 2    | FAIL. An expected rule was exercised and did not alert, the attack script failed, or the install did not complete. |
| 3    | INCOMPLETE. Every rule that ran alerted, but at least one was never exercised because a prerequisite was missing.  |

A skip is deliberately not a pass. A rule the run never exercised has not been certified, and this is a release gate, so 3 is a failure for the purposes of shipping. It is distinguished from 2 because the fix is on the VM rather than in the product, and reporting an unrun step as a detection miss pointed at the wrong subsystem for long enough to be worth its own exit code.

## Running

Required environment:

    EDR_SERVER_URL=https://edr.local:8088     # no trailing slash
    EDR_SESSION_COOKIE=<paste from devtools>  # see "Auth flow" below
    VM_SSH_TARGET=victor@192.168.64.7         # edr-qa, SIP on. NOT edr-dev.

`VM_SSH_TARGET` has a default (`victor@192.168.64.7`). The other two are required for a real run and the driver exits 1 without them, but `--dry-run` skips that validation entirely, so a dry run needs only a loadable scenario name. Nothing else is read.

Older revisions of this runbook also listed `EDR_ADMIN_EMAIL` and `EDR_ADMIN_PASSWORD` as optional pass-throughs to the `scripts/qa/*.sh` wrappers. No consumer for either exists anywhere in the tree, so exporting them does nothing. Do not paste an admin password into your shell for this: the driver authenticates with `EDR_SESSION_COOKIE` and nothing else.

### Auth flow

The server has no password-based `POST /api/session` route; login is OIDC (browser redirect to dex / IdP) or break-glass WebAuthn (passkey, browser-only). Neither is shell-scriptable. The realistic L5 mechanic is to do ONE browser login, copy the `edr_session` cookie value from devtools (Application → Cookies → `edr_session`), export it as `EDR_SESSION_COOKIE`, and reuse it across many scenario runs until the session expires.

The driver verifies the cookie up front by calling `GET /api/session`. If that returns 401, the cookie is expired and the driver fails fast: repeat the browser login.

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

`edr-qa` (192.168.64.7) runs with SIP enabled + Gatekeeper enabled + auto-update disabled, all six toggles flipped off so the macOS version does not drift between snapshot revert and test. That matches what a pilot customer's MDM-deployed Mac actually looks like, which is what L5 must validate against.

`edr-dev` (192.168.64.5) runs with SIP disabled for fast iteration. Running L5 there would catch nothing extra over L0/L4 and would contaminate `edr-qa`'s "clean-pre-install" snapshot if we cross-wired them. The VM environment requirements (SIP enabled, Gatekeeper enabled, snapshot-restored per run, no Xcode / Homebrew) are spelled out in the L5 section of [`testing-strategy.md`](../../docs/testing-strategy.md).

## Adding a new scenario

1.  Create `scripts/uat/scenarios/<name>/`.
2.  Drop in an `attack.sh` (executable). It receives:
    - `UAT_VM_SSH_TARGET` -- ssh target
    - `UAT_HOST_ID` -- the VM's host_id on the server
    - `UAT_SCRIPT_DIR` -- scripts/uat/ absolute path (for sourcing lib/common.sh) It should exit 0 on its own assertions passing, non-zero otherwise.
3.  Drop in an `expected.yaml`. Schema (indented as YAML; `# comments` are tolerated on any line, since the driver's awk parser strips inline comments before extracting values):

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

4.  Drop in a `README.md` describing what the scenario proves and what it does not.
5.  Verify with `scripts/uat/system-test.sh <name> --dry-run` -- the driver loads the YAML, walks the orchestration, and reports per-rule "would-poll-for" lines.

## CI integration

Per-PR: NOT integrated. L5 wall-time is too high for per-PR throughput, and the GitHub-hosted macOS runner pool can't expose the ESF entitlement or run nested virtualisation: L5 needs a real Mac with a SIP-enabled guest. Per-PR drift in extension wire shapes is caught by L0 unit (M7) plus L0 corpus replay (M8); per-PR drift in catalog rules is caught by L6 detection efficacy (M10) on the nightly cadence.

Today: M11 ships the local-execution flavour (`task uat:l5 -- attack-runbook ...`). The harness runs manually on the developer's machine; the asserted-scenario shape means a manual run still produces a clear pass/fail signal suitable for a release-candidate checklist.

Future: a `.github/workflows/system-test.yml` invoking this driver on a self-hosted runner that owns the VM. That work is preserved in the `m11-runner-future-work` branch and tracked as [issue #220](https://github.com/getvictor/fleet-edr/issues/220).
