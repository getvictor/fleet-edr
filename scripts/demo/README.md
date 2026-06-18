# Demo scripts

Self-contained scripts that fire a real Fleet EDR detection on a live host, for demos and hands-on walkthroughs. Unlike the synthetic efficacy corpus (`test/efficacy/corpus/`, which replays events through the fakeagent library with no host) and the SSH-driven QA harness (`scripts/qa/`, `scripts/uat/`, which drive a VM from your workstation), each script here runs **directly on the enrolled Mac** and narrates what it is doing as it goes.

| Script              | Detection it triggers | ATT&CK                  |
| ------------------- | --------------------- | ----------------------- |
| `trigger-dns-c2.sh` | `dns_c2_beacon`       | T1071.004 (+ T1568.002) |

## Prerequisites

- An Apple Silicon Mac on macOS 13+ with the agent installed, the system + network extensions active, and Full Disk Access granted. See [`docs/install-agent-manual.md`](../../docs/install-agent-manual.md).
- Outbound internet from that host: the beacon resolves a [nip.io](https://nip.io) name over plain UDP DNS (which the proxy sees, unlike DoH/DoT) and opens a real outbound TCP connection to the resolved address.
- The Fleet EDR server reachable with this host enrolled, so the alert surfaces in the UI.

## `trigger-dns-c2.sh`

Simulates the classic "malware phones home" chain: a payload staged to `/tmp` resolves a domain and then connects to the address that lookup returned, all from the same process. The `dns_c2_beacon` rule correlates the temp-path `exec`, the `dns_query`, and the `network_connect` into a single finding.

```sh
# On the enrolled Mac:
./trigger-dns-c2.sh            # critical: high-entropy DGA-like domain -> T1071.004 + T1568.002
./trigger-dns-c2.sh high       # high:     ordinary short domain        -> T1071.004
```

Within a few seconds a **DNS C2 beacon** alert should appear in the EDR UI, attributed to the staged `/tmp/beacon.*` process, citing both the DNS lookup and the outbound connection. The script copies `/usr/bin/curl` to a unique `mktemp` path under `/tmp` and re-signs it ad-hoc (a plain copy of an Apple platform binary is SIGKILLed when run from `/tmp`, so it would emit no telemetry), then removes it on exit.
