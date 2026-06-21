# DNS monitoring on macOS

See https://fleetdm.com/guides/monitor-dns-traffic-on-macos for background on how DNS works on macOS, encrypted DNS challenges, and mitigation strategies.

## Implementation notes for this EDR

- **NEFilterDataProvider** (`network_connect` events): the `remoteHostname` property provides hostname info for connections without separate DNS capture. Works reliably for WebKit-based apps but may only return IP addresses for Chromium-based browsers.

- **NEDNSProxyProvider** (`dns_query` events): intercepts queries before `mDNSResponder` sends them upstream. Must forward queries to an upstream resolver since it replaces the system resolver in the chain. Reference implementation: https://github.com/objective-see/DNSMonitor

## Troubleshooting: DNS resolution broken on an endpoint

Use this runbook when an endpoint can reach IP addresses but cannot resolve names ("I can `ping 8.8.8.8` but `ping google.com` fails", browsers stall on lookups). The brief safety note in `lessons-and-gotchas.md` ("DNS proxy can break all DNS resolution") points here.

### Why our agent can cause this

`DNSProxyProvider` (`extension/edr/networkextension/DNSProxyProvider.swift`) is an `NEDNSProxyProvider` that is on by default. Its `handleNewFlow` returns `true` for every UDP and TCP DNS flow, so once active it becomes the **sole resolver** for the whole machine: the OS stops sending claimed DNS flows anywhere else. A query is answered only if the proxy's own `NWConnection` to the upstream server reaches `.ready`, sends, receives, and writes the reply back. If that upstream connection fails or the proxy process wedges, every claimed query goes unanswered and all name resolution dies. ICMP and direct-IP traffic are not DNS flows, so they are never claimed and keep working: that asymmetry is the fingerprint of a broken DNS proxy.

The **agent** (the Go daemon) is not in the resolution path. DNS forwarding lives entirely in the extension; the only agent-facing call is fire-and-forget telemetry (`XPCServer.shared.send`, dispatched async), so a slow or dead agent, a full receiver channel, or "receiver event channel full" log spam cannot delay or fail a lookup. Rule the agent out and look at the network extension.

### Triage: split resolver from transport

```bash
ping -c 2 8.8.8.8                          # raw IP reachability (unproxied)
dig +time=3 +tries=1 @8.8.8.8 google.com   # explicit server over UDP (goes through our proxy)
dig +time=3 +tries=1 google.com            # system resolver
```

- Ping works but `dig @8.8.8.8` times out: a flow-level interception is eating UDP/53. With our DNS proxy active that is the prime suspect.
- `dig @8.8.8.8` works but `dig google.com` fails: a resolver-config problem (scoped resolvers, search domains). Our proxy does not touch that, so it is not the cause.

### Confirm it is our extension, and the decisive test

Read the network extension's own unified log (not the agent log). On macOS the `log` name collides with a zsh builtin, so always use the absolute path `/usr/bin/log`.

```bash
# Is the proxy in the resolution path right now? Run a query and watch for "DNS query:" lines.
/usr/bin/log stream --predicate 'subsystem == "com.fleetdm.edr.networkextension" AND category == "DNSProxy"' --info --debug --style compact &
dig google.com >/dev/null; sleep 1; kill %1

# What failed during the outage window? Errors are .error level and persist in the store.
/usr/bin/log show --predicate 'subsystem == "com.fleetdm.edr.networkextension" AND category == "DNSProxy"' \
  --info --start "YYYY-MM-DD HH:MM:SS" --end "YYYY-MM-DD HH:MM:SS" --style compact | grep ' E '
```

Failure signatures, from most to least diagnostic:

- `Upstream UDP connection failed`: the proxy claimed the query but its own connection to the upstream resolver failed. A dense burst (hundreds in one minute, many sharing a millisecond) means every in-flight query failed at once: a real outage. This was the dominant signature in the 2026-06-20 incident on the primary dev Mac (974 such errors clustered at 21:21, while ping kept working; only a reboot cleared it).
- `Failed to write UDP response: the flow is not connected` and `Failed to open UDP flow: the peer closed the flow`: usually benign at low rates (the client gave up before the upstream reply arrived). A sustained flood means clients are timing out because the proxy is too slow or stuck.
- `TCP connection failed`: the upstream TCP DNS (DoT/large response) path failed.

The single test that settles causation: **disable our DNS proxy and see if resolution recovers.**

- Fastest: **reboot** the endpoint. This tears down the proxy config and the wedged process; if DNS comes back, our proxy was holding it.
- Targeted: run the host-app subcommand `disable-dns-proxy`, which flips `NEDNSProxyManager.isEnabled = false` (`extension/edr/edr/main.swift`). Re-enable later with `enable-dns-proxy`.

```bash
'/Applications/Fleet EDR.app/Contents/MacOS/edr' disable-dns-proxy
```

If DNS recovers the moment the proxy is off, our extension caused it. If it stays broken, look elsewhere (upstream resolver down, VPN, captive portal).

### Caveats when driving this over SSH

- `NEDNSProxyManager.loadFromPreferences` talks to `nesessionmanager` over XPC and can hang forever from an SSH session with no GUI login, so `enable-dns-proxy` / `disable-dns-proxy` may never return. Run them from a GUI Terminal (Screen Sharing) on the box, or just reboot.
- Running the host-app binary with no arguments enters a long-running notify-mode `NSApplication` and does not exit: do not invoke it bare over SSH expecting help text.
- Always connect by **IP**, not hostname: if you are debugging a DNS outage, hostname-based SSH will also fail. Keep an IP-based session open before you toggle anything.

### Where the evidence lives

- Network extension logs: unified log store, subsystem `com.fleetdm.edr.networkextension`, categories `DNSProxy` / `NetworkFilter` / `XPCServer`. The store (`/var/db/diagnostics`) keeps roughly a few days; `.debug` lines (including the per-query `DNS query:` lines) are not persisted, so capture them live with `log stream --debug`. `.error` lines do persist, which is what makes a past outage reconstructable.
- Confirm the extensions and their PIDs with `systemextensionsctl list` (look for `com.fleetdm.edr.networkextension ... [activated enabled]`).
