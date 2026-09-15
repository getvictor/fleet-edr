# network-containment scenario

L5 system test for host network containment (issues #948 and #584). It contains the VM through the operator API, checks on the VM what containment promises, releases it, and checks the network is back.

## What it covers

The unit and integration tests prove each piece of containment in isolation: the server records the state and queues the command, the agent resolves the lifeline and completes only on the extension's confirmation, the extension builds the filter settings and the DNS proxy's decisions. None of them proves that a real host, with the shipped agent and both extensions, is actually cut off and still reachable. This scenario does, through the same API the console uses:

| Assertion                                                                 | Asserted from                                |
| ------------------------------------------------------------------------- | -------------------------------------------- |
| the host applies containment with a non-empty lifeline, and confirms it   | the server's delivery result for the change  |
| a new connection to an address outside the lifeline fails while contained | the probe's samples                          |
| a name other than the server's is answered REFUSED while contained        | the probe's samples                          |
| the EDR server stays reachable from the host while contained              | the probe's samples                          |
| inbound SSH is refused while contained                                    | an SSH attempt from the workstation          |
| the release reaches the contained host and is applied                     | the server's delivery result for the release |
| the host reaches the network and resolves names again after the release   | the probe's samples                          |
| the same probe reached the network and resolved names before containment  | the probe's samples                          |

The last row is what gives the others meaning: a probe that could not reach the outside even on a free host would pass every "blocked" check.

SSH is cut while the host is contained, so the VM cannot be asked anything mid-test. The script starts a probe on the VM before containing it. The probe writes a sample every few seconds: the HTTP status of `https://1.1.1.1/` (by address, so a DNS failure cannot pass for a blocked connection), the DNS status `dig` gets for `example.com`, and the HTTP status of the server's `/livez`. The script reads the log after the release and sorts the samples into before, contained and after, by the times it saw each change confirmed, converted to the VM's clock.

The scenario raises no alert, so `expected.yaml` has no `rules:` block and the driver passes on the script's exit status.

## Running it

```bash
VM_SSH_TARGET=victor@192.168.64.7 \
UAT_SSH_KEY=$HOME/.ssh/id_ed25519 \
UAT_INSECURE=1 \
EDR_SERVER_URL=https://192.168.64.1:8088 \
EDR_SESSION_COOKIE=<edr_session cookie value> \
task uat:l5 -- network-containment --skip-install
```

It takes about three minutes.

- `EDR_SERVER_URL` must be the URL the agent enrolled with (`/etc/fleet-edr.conf` on the VM). The lifeline allows only the agent's own server endpoint, so a different address for the same server is blocked while the host is contained and the scenario fails on the server samples.
- Containing a host needs `host.isolate` and a recent authentication: the session must have signed in within `EDR_REAUTH_WINDOW` (30 minutes by default). An older session is refused with `reauth_required`, which the script reports before anything is contained.
- The host must not be contained when the run starts. The script will not lift a containment it did not ask for.

## Leaving the host released

The exit trap releases the host whenever the script contained it and did not see the release confirmed, including on a failed assertion or an interrupt. If that release is refused too (an expired session, say), the script says so; release the host from its page in the console. A probe the script never stopped exits on its own after 15 minutes.

## VM prerequisites

Key-based SSH for `VM_SSH_TARGET`, `dig` and `curl` (both ship with macOS), and outbound access to `1.1.1.1` and DNS on the VM before the run. No sudo.
