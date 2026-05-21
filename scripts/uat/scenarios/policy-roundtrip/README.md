# policy-roundtrip scenario

L5 system-test wrapper around `scripts/qa/e2-policy-roundtrip.sh`. Exercises
the full blocklist policy round-trip:

1. Authenticate to the admin REST API.
2. Capture the existing policy (so we can restore it on exit).
3. PUT a synthetic blocked path into the policy.
4. Wait up to 60s for the agent on the VM to ack the new policy and write
   `/var/db/com.fleetdm.edr/policy.json`.
5. SSH into the VM and try to exec the blocked path. Expect the
   extension's `ES_AUTH_RESULT_DENY` to surface as a non-zero exit / the
   "Operation not permitted" string from the shell.
6. Restore the original policy.

## What this proves

The control plane works in BOTH directions on a SIP-enabled host:

- Server -> agent: the policy reaches the agent (XPC handshake + policy
  decoder + persist path all good).
- Agent -> extension: the agent updates the extension's
  `ApplicationControlStore` via XPC (the M9-injectable `storagePath` from
  M7 stays out of the way here; production uses `.shared`).
- Extension -> kernel: the AUTH_EXEC callback returns DENY on a real exec
  attempt (the ESF + cdhash / signing-id / path matching logic that's
  tested in isolation by `ApplicationControlStoreTests` is also live in
  the kernel callback path).

## Why `expected.yaml` has no `rules:` block

There is no `blocked_exec` detection rule in the v0.1 catalog -- the block
itself happens in the kernel via AUTH_EXEC; surfacing a paired alert in
the UI is open future work tracked separately. The scenario's assertion
is `attack_sh_exit_zero`: the inner script encodes the full chain and
exits non-zero on any failure, so the driver just propagates that.

When the `blocked_exec` (or equivalent) rule lands, append a `rules:`
block to `expected.yaml` here; the driver picks it up automatically.

## Running

    EDR_SERVER_URL=https://edr.local:8088 \
    EDR_ADMIN_EMAIL=admin@fleet-edr.local \
    EDR_ADMIN_PASSWORD=<paste-from-boot-log> \
    VM_SSH_TARGET=victor@192.168.64.7 \
      scripts/uat/system-test.sh policy-roundtrip

The inner `scripts/qa/e2-policy-roundtrip.sh` is rerunnable: it always
captures the original policy on entry and restores it on exit, even on
early-fail paths (its `trap` handler restores before exiting non-zero).
That makes this scenario safe to run repeatedly against the same VM.
