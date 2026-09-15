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

A narrow lifeline of the server address alone was not enough. A DHCP lease renewal during containment lost the host's address until release, and every name lookup failed, because all DNS passes through this product's DNS proxy, whose own forwards the filter drops unless a rule allows them.

With DHCP and DNS in the lifeline, a direct query to the configured resolver (`dig`) resolves while the host is contained, but the system resolver does not: `mDNSResponder` sends no query at all (the DNS proxy sees none) and `getaddrinfo` callers get no address. The agent therefore resolves the server name with a direct resolver query while contained.

## What changes

The work lands in steps, producer before consumer.

### Network extension (this step)

- **Containment is enforced by filter settings.** Contained, the content filter's settings allow the lifeline and drop everything else, which the operating system enforces without consulting the provider. Not contained, the settings are the telemetry settings the filter already uses, with one addition after a release: the released containment's TCP flows to the EDR server stay allowed by rule until the filter next starts. Measured on edr-dev, releasing straight to the telemetry settings cut a connection opened while contained within two seconds (the rules decided it, so the provider never saw it), and after an extension restart while contained it cut the agent's control stream and with it the release command's outcome. With the server flows kept by rule, connections opened before containment, during it, and across an extension restart all survived the release.
- **The lifeline** is TCP to each EDR server address on the server port, DHCP from the client port to the server port (UDP 68 to 67, and 546 to 547 for DHCPv6; only a privileged process can bind the client port), and DNS (TCP and UDP 53). Loopback is never filtered. Until the DNS proxy step lands, DNS to any address stays open on a contained host; that step lands before any operator can contain a host.
- **The state is persisted and ordered.** A `network_containment.update` from the agent carries the server's version and epoch, whether the host is contained, and the server endpoint the agent resolved. The extension persists it before applying it, applies it as the first settings of a starting filter, orders updates by epoch then version, and accepts an update at the same version that only moves the server endpoint, so the agent can refresh the addresses of a contained host. A containment with no usable lifeline is refused whole.
- **The extension reports containment status** (contained, version, epoch, whether it applied) to the agent after each change and on every agent hello, and sends nothing on a host that has never received a containment update, so an agent without containment support uploads no stray control events. Filter applies run one at a time, so settings never take effect out of order.
- While contained, the filter records no `network_connect` events: dropped flows never reach the provider.

### Agent

- **`set_network_containment`** (`version`, `epoch`, `contained`) resolves the lifeline, the endpoint the agent reaches the server through (the server, or its proxy), with a direct resolver query, since the system resolver answers nothing while contained. It sends the extension its document and completes only when the extension reports that state applied, so the console can say a host is contained on the strength of the command's result. It fails with the reason when the lifeline cannot be resolved (nothing is sent), when the extension cannot be reached, does not apply the state or reports a newer one, or on a host without the network extension.
- **A contained host reaches the server through its lifeline.** Uploads, command polls, token refresh and re-enrollment, and the control channel dial the lifeline addresses while the host is contained. A proxied control channel keeps gRPC's own proxy dialing.
- **The lifeline stays current.** While contained the agent re-resolves every five minutes and sends new addresses at the same version when they moved; an agent that starts on a contained host learns it from the extension's status and refreshes once. The extension's status events are consumed and never uploaded.

### Later steps

- DNS proxy: while contained, answer only the EDR server's name, so DNS cannot carry traffic out of a contained host.
- Server: containment state per host, a contain and release API with a required reason, audit, delivery with catch-up, and the state on the host API.
- Console: contain and release on the host, with the reason and step-up reauthentication, and the state on the host list and header.

## Out of scope

- Keeping operator-chosen addresses reachable during containment (#1059).
