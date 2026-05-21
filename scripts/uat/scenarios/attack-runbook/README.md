# attack-runbook scenario

L5 system-test wrapper around `scripts/qa/attack-runbook.sh` (the dogfood
runbook that fires every shipped detection rule via reverse-engineered
positive triggers). This scenario asserts that the rules listed in
`expected.yaml` each produced an alert against the VM's host_id on the
server, within the per-rule SLA.

## What this proves

The full chain works end-to-end on a SIP-enabled / Gatekeeper-enabled
macOS host: extension produces events, agent uploads them, server ingests
them, detection engine matches the catalog rules, alerts land in the REST
API. Any silent break in that chain (an XPC handshake regression, a wire
shape drift unwired by `EventSerializerTests`, a detection rule that
matches the unit tests but not real ESF emissions) surfaces here as a
"miss" against an expected rule_id.

## What this does NOT prove

- `shell_from_office` and `blocked_exec`: deliberately omitted. The first
  needs Microsoft Office on the VM (not installed); the second has no
  matching detection rule in the v0.1 pack (see `scripts/qa/README.md`
  "Known gaps").
- False-positive rate on ambient noise: this scenario fires attacks
  back-to-back, so a FP that fires within the 120s window from any of
  the synthetic events wouldn't show up as a per-rule "miss". The L6
  efficacy harness (M10) adds the ambient-noise lane.

## Running

The driver picks this scenario up via its directory name:

    EDR_SERVER_URL=https://edr.local:8088 \
    EDR_ADMIN_EMAIL=admin@fleet-edr.local \
    EDR_ADMIN_PASSWORD=<paste-from-boot-log> \
    VM_SSH_TARGET=victor@192.168.64.7 \
      scripts/uat/system-test.sh attack-runbook

Add `--skip-install` to skip the PKG install + extension-activation wait
when iterating against an already-enrolled VM. Add `--dry-run` to walk
the orchestration shape without actually SSH-ing or curl-ing.

## Regenerating the rule list

When `server/rules/internal/catalog/` gains a new rule that the runbook
should fire, edit BOTH `scripts/qa/attack-runbook.sh` (add the step) and
this directory's `expected.yaml` (add the rule_id). The pair lands in the
same PR.
