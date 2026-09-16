# Host network containment

## Why

Issues #948 and #584. Containing a compromised host (cutting it off from the network while it stays reachable by the EDR server) is among the most used response actions in an incident, and the product does not have it. The archived `resilient-network-enforcement` change specified it and was never built; ADR-0014 names the failure semantics it must keep: containment is an explicit decision, enforced locally, persisted, re-applied on restart, and it always preserves a lifeline to the EDR server.

## What was measured

On edr-dev (macOS 26.3) with a measurement-only build, comparing the two ways a content filter can drop flows:

| Behaviour | Filter settings, default action drop | Per-flow verdict in `handleNewFlow` |
| --- | --- | --- |
| New connections elsewhere | blocked within a second, ICMP included | blocked, attributed to the process |
| Established connections elsewhere | cut within the same second | keep flowing |
| Provider stopped for 20 s | containment holds | new flows undecided |
| Provider killed | containment holds through the restart | leaks for about 5 s |

A narrow lifeline of the server address alone was not enough. A DHCP lease renewal during containment lost the host's address until release, and every name lookup failed, because all DNS on that host passed through this product's DNS proxy, which was running, and the filter drops its forwards unless a rule allows them.

With DHCP and DNS in the lifeline, a direct query to the configured resolver (`dig`) resolves while the host is contained, but the system resolver does not: `mDNSResponder` sends no query at all (the DNS proxy sees none) and `getaddrinfo` callers get no address. The agent therefore resolves the server name with a direct resolver query while contained.

## What changes

The work lands in steps, producer before consumer.

### Network extension

- **Containment is enforced by filter settings.** Contained, the content filter's settings allow the lifeline and drop everything else, which the operating system enforces without consulting the provider. Not contained, the settings are the telemetry settings the filter already uses, with one addition after a release: the released containment's TCP flows to the EDR server stay allowed by rule until the filter next starts. Measured on edr-dev, releasing straight to the telemetry settings cut a connection opened while contained within two seconds (the rules decided it, so the provider never saw it), and after an extension restart while contained it cut the agent's control stream and with it the release command's outcome. With the server flows kept by rule, connections opened before containment, during it, and across an extension restart all survived the release.
- **The lifeline** is TCP to each EDR server address on the server port, DHCP from the client port to the server port (UDP 68 to 67, and 546 to 547 for DHCPv6; only a privileged process can bind the client port), and DNS (TCP and UDP 53) to the host's configured resolvers, and to no other address. Loopback is never filtered. Which names resolve is restricted by the DNS proxy (below); which resolvers can be reached is restricted here, because a host can be contained with the proxy off or stopped, and DNS to a resolver of the caller's choosing carries data out of the host. A host with no known resolver is allowed no DNS, which is the set its own agent would query anyway.
- **The state is persisted and ordered.** A `network_containment.update` from the agent carries the server's version and epoch, whether the host is contained, and the server endpoint the agent resolved. The extension persists it before applying it, applies it as the first settings of a starting filter, orders updates by epoch then version, and accepts an update at the same version that only moves the server endpoint, so the agent can refresh the addresses of a contained host. A containment with no usable lifeline is refused whole.
- **The extension reports containment status** (contained, version, epoch, whether it applied) to the agent after each change and on every agent hello, and sends nothing on a host that has never received a containment update, so an agent without containment support uploads no stray control events. Filter applies run one at a time, so settings never take effect out of order.
- While contained, the filter records no `network_connect` events: dropped flows never reach the provider.

### Agent

- **`set_network_containment`** (`version`, `epoch`, `contained`) resolves the lifeline, the endpoint the agent reaches the server through (the server, or its proxy), with a direct resolver query, since the system resolver answers nothing while contained. It sends the extension its document and completes only when the extension reports that state applied, so the console can say a host is contained on the strength of the command's result. It fails with the reason when the lifeline cannot be resolved (nothing is sent), when the extension cannot be reached, does not apply the state or reports a newer one, or on a host without the network extension.
- **A contained host reaches the server through its lifeline.** Uploads, command polls, token refresh and re-enrollment, and the control channel dial the lifeline addresses while the host is contained. A proxied control channel keeps gRPC's own proxy dialing.
- **The lifeline stays current.** While contained the agent re-resolves every five minutes and sends new addresses at the same version when they moved; an agent that starts on a contained host learns it from the extension's status and refreshes once. The extension's status events are consumed and never uploaded.

### DNS proxy

- **A contained host resolves only the EDR server's name.** The containment document carries the lifeline's host names, and while the host is contained the DNS proxy forwards a single-question query only for one of them (case-insensitive, label by label), answers every other query locally with REFUSED, drops what is not a query, and resolves nothing over TCP. The filter's lifeline allows DNS so the agent can resolve the server, and only to the host's configured resolvers. The two layers restrict different things: the filter decides which resolvers a contained host may reach, always, and the proxy decides which names resolve, while it is running. A host contained with the proxy disabled or stopped can still resolve any name its own resolvers answer (#1078). Refused lookups are still recorded as `dns_query` events.

### Server

- **Desired state per host.** `POST /api/hosts/{host_id}/containment` (`contained`, `reason`) records the state at the host's next version with the change time as its epoch, queues `set_network_containment` for the host, and audits `host.contain` or `host.release`. It is authorized as `host.isolate`, which the chokepoint already gates on a recent authentication for an interactive session, and refuses a blank reason or a host with no active enrollment. Asking for the state the host already has changes nothing. `GET` on the same path returns the state and its delivery.
- **Delivery with catch-up.** Every five minutes the server queues a host's state again when its latest command does not deliver it (none, another state, expired or cancelled, failed six hours ago, or queued before the host last enrolled), mirroring the watched-path catch-up per host.
- **No generic containment command.** `POST /api/commands` no longer accepts the unused `isolate` reservation and never accepts `set_network_containment`, so containment changes only through the recorded state.

### Console

- **The host header shows containment and offers the action.** A badge says Containing, Contained, Containment failed, Releasing or Release failed, re-read every few seconds while a change is on its way. An operator holding `host.isolate` gets Contain host or Release host, which asks for a reason in a confirmation that says what containment does, through the existing reauthentication prompt.
- **The host list marks hosts under containment,** from `GET /api/containment`, which lists every host with a containment state and its delivery.

### Acceptance

- **An end-to-end system test.** The L5 scenario `network-containment` contains a host through the API, samples its network from a probe while SSH is cut, and releases it. It ran on edr-dev with this change's agent and extensions; edr-qa runs it against the release candidate, since it needs a signed build.
- **The operator guide and the release notes.**

## Out of scope

- Keeping operator-chosen addresses reachable during containment (#1059).
