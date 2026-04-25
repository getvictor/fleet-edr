# Phase-7 dogfood QA scripts

Four scripts plus this README make up the Phase-7 dogfood QA harness
(plan reference: `claude/mvp/phase-7-pilot-hardening.md` Track E).
Each script is self-contained and runnable from this workstation; the
work happens via `ssh` to the dev VM.

| Script | Plan item | Phase 7 milestone | Approx wall time |
|---|---|---|---|
| `attack-runbook.sh` | E1 | Synthetic attacker fires every shipped detection rule | ~2 min |
| `e2-policy-roundtrip.sh` | E2 | Blocklist policy push → agent pickup → blocked exec | ~3 min |
| `e3-network-partition.sh` | E3 | 10-minute network partition + queue drainage | ~12 min |
| `e4-uninstall.sh` | E4 | Uninstaller round-trip + offline detection | ~7 min |

## Prerequisites

Before running any script:

- **Server**: Fleet EDR server reachable, admin credentials in hand,
  at least one host enrolled. The server is responsible for the
  policy fan-out + alert ingestion these scripts exercise.
- **VM**: agent installed + sysext active + Full Disk Access granted.
  Verified via the manual install doc (`docs/install-agent-manual.md`).
  SSH from this workstation works without an interactive password
  prompt — either keys in `~/.ssh/authorized_keys` or `sshpass` in
  the wrapper. The scripts use `BatchMode=yes` so a missing key
  fails fast rather than hanging.
- **Tooling on this workstation**: `bash`, `curl`, `jq`, `ssh`,
  `scp`, `shellcheck` (optional — only for editing the scripts).
  The scripts avoid bash-4-only features so macOS's bundled
  bash 3.2 works.
- **Tooling on the VM**: `sqlite3` (for E3 queue depth checks),
  `pfctl` (for E3 partition; ships with macOS), `plutil` (for
  reading `host_id` from the persisted enrollment). All present in
  base macOS.

## Common environment variables

Every script reads the same four env vars; E3 additionally requires
`EDR_SERVER_IP`:

```sh
export EDR_SERVER_URL='https://edr.local:8088'   # NO trailing slash
export EDR_ADMIN_EMAIL='admin@fleet-edr.local'
export EDR_ADMIN_PASSWORD='<paste from server boot log>'
export VM_SSH_TARGET='victor@192.168.64.5'
export EDR_SERVER_IP='192.168.64.1'              # E3 only
```

The admin password prints once at server first-boot
(`SEEDED ADMIN USER` log line). If you missed it, see the recovery
note in `docs/install-server.md`.

## Running the suite

Run the four scripts in order. They're rerunnable for QA, but not
strictly idempotent — some intentionally change VM state. E2 captures
the original blocklist on entry and restores it on exit (including
early-exit paths). E3 records pf's enabled/disabled state before the
partition and rolls back to that state on exit. E4 removes the agent
by design; rerun with `--reinstall` to put it back.

```sh
bash scripts/qa/attack-runbook.sh             # E1
bash scripts/qa/e2-policy-roundtrip.sh        # E2
bash scripts/qa/e3-network-partition.sh       # E3 (or --short for 60s)
bash scripts/qa/e4-uninstall.sh               # E4 (run last; it removes the agent)
```

E4 is destructive in the "agent is gone afterwards" sense — keep it
last. Add `--reinstall path/to/fleet-edr-vX.Y.Z.pkg` to E4 to also
exercise the re-install half (proves `/etc/fleet-edr.conf` is preserved
across the round-trip).

## Filing the QA report

After running the suite, capture the results in
`claude/mvp/phase-7-qa-YYYY-MM-DD.md` following the Phase 5 template.
The report should record:

- Per-milestone PASS / FAIL with one-line evidence.
- Any deviations (e.g. E3 `--short` because the operator was iterating).
- Anything observed that wasn't in the plan: stale alerts, log
  warnings, UI glitches.
- Open issues to file before pilot ship-go.

The report is the gating Phase-7 acceptance deliverable
(`claude/mvp/phase-7-pilot-hardening.md` E5).

## Known gaps the scripts surface

These are deliberate — the scripts assert what's wired today and
report on what isn't, rather than failing loudly on aspirational
behaviour:

- **E2 / `blocked_exec` alert**: the extension blocks the exec via
  `ES_AUTH_RESULT_DENY` (works), but no detection rule fires a
  matching alert in the UI (`blocked_exec` rule_id doesn't ship in
  the v0.1 detection pack). Tracked for Phase 8. The script reports
  the open-alert count for the host as informational, doesn't
  assert it's nonzero.
- **E3 / per-host event count endpoint**: there isn't one in the
  v0.1 admin API surface. The script verifies queue drainage
  on the agent side and the open-alert count server-side, but a
  precise "no duplicates" check needs a direct DB query — out of
  scope for a script that runs only against published APIs.
- **E4 / sysext deactivation timing**: macOS occasionally takes a
  few seconds longer than the uninstall script waits to fully
  deactivate the sysext. If `systemextensionsctl list` still shows
  `activated terminating` immediately after step 3, give it 30s and
  recheck — that's expected and not a regression.
