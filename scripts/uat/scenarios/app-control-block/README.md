# app-control-block scenario

L5 system/VM coverage for **Application Control active blocking** — the half of
the App Control story that detection scenarios (attack-runbook) do not exercise.

It is the replacement for the removed `e2-policy-roundtrip.sh` blocklist scenario
(`scripts/qa/README.md` "Known gaps"): when the singleton `/api/policy` blocklist
became the per-policy `/api/v1/app-control/*` surface (#289 / #290), the old L5
scenario was deleted and its replacement was "tracked separately". This is it. It
is also the missing half of the #301 acceptance gate ("Application Control still
works", VM-validated on a SIP-on host).

## What it does

1. Stages a deterministic non-platform block target on the VM (a copy of
   `/bin/echo`; copying drops the kernel `is_platform_binary` attribution so the
   platform carve-out does not exempt it).
2. Confirms the target runs + is allowed at baseline.
3. POSTs a `BINARY` BLOCK rule on the copy's SHA-256 to the seeded Default policy.
4. Polls until the snapshot fan-out reaches the host and the exec is **DENIED**
   (host-side enforcement), then fires a couple more denied execs.
5. The driver asserts the resulting `application_control_block` alert
   (`expected.yaml`).

Cleanup deletes the rule and the target on exit.

## Run

    task uat:l5 -- app-control-block --skip-install   # against an enrolled VM
    task uat:l5 -- app-control-block                  # full install + scenario

Same required env as attack-runbook (see `../../README.md`): `EDR_SERVER_URL`,
`EDR_SESSION_COOKIE`, `VM_SSH_TARGET`, and `UAT_INSECURE=1` for the local dev cert.
