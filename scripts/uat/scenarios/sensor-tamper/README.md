# sensor-tamper (L5)

Switches off the EDR's own content filter on a live VM and asserts the `sensor_tamper` alert (T1562.001, issue #684).

## What this covers that L6 cannot

The synthetic corpus scenario (`test/efficacy/corpus/T1562.001-sensor-tamper/`) injects a `sensor_provider_transition` event that already exists, so it proves the rule reads that event correctly and nothing else. Four pieces of production code sit upstream of the rule and are never executed by it:

1. Stopping a real provider makes the extension notice.
2. The extension grades the stop a fault rather than a supported opt-out (issue #649).
3. The agent diffs its liveness reports into a transition event (issue #685).
4. The event reaches the server.

This scenario exercises all four on a real host. It is the difference between "the rule is correct" and "the detection works".

## Running it

```bash
VM_SSH_TARGET=victor@192.168.64.5 \
UAT_SSH_KEY=$HOME/.ssh/id_ed25519 \
UAT_INSECURE=1 \
EDR_SERVER_URL=https://127.0.0.1:8088 \
EDR_SESSION_COOKIE=<edr_session cookie value> \
task uat:l5 -- sensor-tamper --skip-install
```

`--skip-install` targets an already-enrolled VM. Drop it (and pass `--pkg-path=`) to exercise the install path too, but note issue #689: a `pkg:dryrun` package cannot activate its extensions, so a dry-run pkg fails before this scenario gets to run.

## VM prerequisites

The driver uses `ssh -o BatchMode=yes`, so the VM needs key auth and passwordless sudo for the two commands this scenario runs. Both are narrow by design:

```sh
# ~victor/.ssh/authorized_keys        <- your UAT_SSH_KEY's public half
# /etc/sudoers.d/edr-uat (mode 440)
victor ALL=(root) NOPASSWD: /Applications/Fleet\ EDR.app/Contents/MacOS/edr, /usr/bin/log
```

`/usr/bin/log` is load-bearing, not convenience. `log show --info` returns another process's info-level messages only to root, so an unprivileged read comes back EMPTY and every provider assertion fails while the provider is behaving perfectly. That failure mode is silent and reads like a broken product, so it is worth knowing before debugging one.

Writing that sudoers file trips the `sudoers_tamper` rule (T1548.003) on the host it is written to. That is the detection working, not a problem, but it explains the extra alert on a freshly prepared VM.

## What it asserts, and where

| assertion                                      | asserted by                                           |
| ---------------------------------------------- | ----------------------------------------------------- |
| the host was capturing before the tamper       | `attack.sh`, from the server's host health            |
| the extension noticed the provider stop        | `attack.sh`, from the VM's unified log                |
| the alert reached the server                   | the driver, polling `/api/alerts` for `sensor_tamper` |
| capture came back and the host is left healthy | `attack.sh`, from the VM's unified log                |

The alert assertion is deliberately the driver's, via `expected.yaml`: the rule id is static, so the driver's own poll is exactly the right check. `attack.sh` asserts only what the driver cannot see.

The recovery wait is not cleanup politeness. The alert has to outlive the repair that hides the tamper from host health, which is the whole reason the rule exists, and the driver's poll runs after that repair has already landed. A scenario that returned early would also leave the next scenario running on a VM with no capture.

`Connection to <vm> closed by remote host` during the recovery wait is expected: the content filter coming back briefly drops the SSH session. The poll tolerates it and reconnects on the next iteration.

## Not automated here

The **upgrade cutover must not alert** half, which is the false-positive case the rule's design turns on. Reproducing it means bumping both extensions' `CFBundleVersion`, re-signing, and re-activating, which mutates installed extension state and reliably drops the SSH session mid-cutover. It was verified manually instead (stop and resume 1.017s apart, no alert, against a tamper's 35.7s), and the synthetic noise scenario `test/efficacy/noise/agent-upgrade-cutover.yaml` pins the same behaviour on every L6 run using the measured gap.
