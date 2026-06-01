# Dogfood QA scripts

Three scripts plus this README make up the pre-pilot dogfood QA harness.
Each script is self-contained and runnable from this workstation; the
work happens via `ssh` to the dev VM.

| Script | What it exercises | Approx wall time |
|---|---|---|
| `attack-runbook.sh` | Synthetic attacker fires every shipped detection rule | ~2 min |
| `e3-network-partition.sh` | 10-minute network partition + queue drainage | ~12 min |
| `e4-uninstall.sh` | Uninstaller round-trip + offline detection | ~7 min |

A fourth script (`e2-policy-roundtrip.sh`) used to exercise the blocklist
policy round-trip via `GET/PUT /api/policy`. The server's blocklist admin
endpoint has been replaced by the per-policy app-control surface
(`/api/v1/app-control/policies/*` etc), which is a fundamentally different
shape; the old script was removed rather than ported. Its replacement over the
app-control admin API is the asserted L5 scenario
`scripts/uat/scenarios/app-control-block/` (it posts a BINARY BLOCK rule,
confirms the extension denies the matching exec, and asserts the
`application_control_block` alert), rather than another interactive `qa/` script.

## Prerequisites

Before running any script:

- **Server**: Fleet EDR server reachable, at least one host enrolled.
- **VM**: agent installed + sysext active + Full Disk Access granted.
  Verified via the manual install doc (`docs/install-agent-manual.md`).
  SSH from this workstation works without an interactive password
  prompt — keys in `~/.ssh/authorized_keys`. The scripts use
  `BatchMode=yes` so a missing key fails fast rather than hanging.
- **Tooling on this workstation**: `bash`, `curl`, `jq`, `ssh`,
  `scp`, `shellcheck` (optional — only for editing the scripts).
  The scripts avoid bash-4-only features so macOS's bundled
  bash 3.2 works.
- **Tooling on the VM**: `sqlite3` (for the network-partition queue-depth
  check), `pfctl` (for the partition itself; ships with macOS), `plutil`
  (for reading `host_id` from the persisted enrollment). All present in
  base macOS.

## Common environment variables

The two server-touching scripts (`e3-network-partition.sh` and
`e4-uninstall.sh`) read the same three env vars; the network-partition
script additionally requires `EDR_SERVER_IP`:

```sh
export EDR_SERVER_URL='https://edr.local:8088'   # NO trailing slash
export EDR_SESSION_COOKIE='<paste edr_session cookie from devtools>'
export VM_SSH_TARGET='victor@192.168.64.5'
export EDR_SERVER_IP='192.168.64.1'              # E3 only
```

`attack-runbook.sh` doesn't talk to the server at all — only SSH access
to the VM is required.

### Auth flow

The server has no password-based `POST /api/session` route; operator
login is OIDC (browser redirect to dex / IdP) or break-glass WebAuthn
(passkey, browser-only). Neither is shell-scriptable. The realistic
dogfood mechanic:

1. Do one browser login (break-glass or OIDC) against the EDR admin UI.
2. Open devtools → Application → Cookies → copy the `edr_session` cookie
   value.
3. `export EDR_SESSION_COOKIE='<paste>'` and reuse across many script
   runs until the session expires (typical session TTL: 1 hour idle,
   8 hours absolute).
4. If a script bails with "GET /api/session failed HTTP 401" the cookie
   has expired — repeat the browser login.

## Running the suite

Run the scripts in order:

```sh
bash scripts/qa/attack-runbook.sh
bash scripts/qa/e3-network-partition.sh       # add --short for a 60s partition
bash scripts/qa/e4-uninstall.sh               # run last; it removes the agent
```

The network-partition script records pf's enabled/disabled state before
the partition and rolls back to that state on exit. The uninstall script
removes the agent by design; rerun with `--reinstall` to put it back.

The uninstall script is destructive in the "agent is gone afterwards"
sense — keep it last. Add `--reinstall path/to/fleet-edr-vX.Y.Z.pkg` to
also exercise the re-install half (proves `/etc/fleet-edr.conf` is
preserved across the round-trip).

## Filing the QA report

After running the suite, capture the results so the pre-pilot
acceptance deliverable has a paper trail. The report should record:

- Per-script PASS / FAIL with one-line evidence.
- Any deviations (for example `--short` on the network-partition
  script because the operator was iterating).
- Anything observed that wasn't planned: stale alerts, log warnings,
  UI glitches.
- Open issues to file before pilot ship-go.

## Known gaps the scripts surface

These are deliberate — the scripts assert what's wired today and
report on what isn't, rather than failing loudly on aspirational
behaviour:

- **Per-host event count endpoint (network-partition)**: there isn't
  one in the v0.1 admin API surface. The script verifies queue
  drainage on the agent side and the open-alert count server-side,
  but a precise "no duplicates" check needs a direct DB query — out
  of scope for a script that runs only against published APIs.
- **Sysext deactivation timing (uninstall)**: macOS occasionally
  takes a few seconds longer than the uninstall script waits to
  fully deactivate the sysext. If `systemextensionsctl list` still
  shows `activated terminating` immediately after step 3, give it 30s
  and recheck — that's expected and not a regression.
