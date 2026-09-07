# extension-network-response Specification

## Purpose

Defines the network extension's DNS-forwarding resilience: a health watchdog that monitors upstream-forwarding health and recovers from sustained failure without operator intervention. When no enforcement policy is active it fails open (resolution returns to the system resolver, availability preserved) and periodically attempts to restore proxying; when a policy is active it never bypasses in a way that would let a blocked domain resolve.

## Requirements

### Requirement: DNS proxy forwards away from another provider's tunnel

An enabled DNS proxy becomes the sole resolver for every flow it claims, so its own upstream forward MUST NOT be routed back into a resolver that is waiting on that forward. When another network extension owns the system default route, forwarding that extension's own resolver query over the default route sends it into that extension's tunnel; it cannot answer until the forward completes, and the forward cannot complete until it answers, so all host name resolution stops.

The system SHALL determine whether a claimed flow originated from another network-extension provider, identified by that process holding the network-extension entitlement rather than by a list of known vendors, and SHALL route that flow's upstream forward so that it cannot leave over a tunnel interface. The system's own provider is exempt: it holds the same entitlement, and the operating system already keeps the system's own outbound connections out of the proxy chain, so no dependency cycle exists.

For every other claimed flow, the system SHALL pin the upstream forward to the interface the client bound its flow to, when the flow reports one, so a forward cannot be silently re-routed onto a path the client did not choose. A flow that is not bound to an interface SHALL keep default routing. A tunnel-avoiding forward SHALL NOT be pinned to the flow's bound interface, because that interface may itself be the tunnel being avoided.

The system MUST NOT decline a DNS flow in order to keep out of another resolver's path. Declining does not return the flow to the operating system: a declined flow is not resolved by any other path, so declining costs the host its name resolution entirely rather than failing open. Forward outcomes for tunnel-avoiding flows SHALL NOT contribute to the forwarding-health accounting that triggers a bypass, because those forwards are denied the tunnel by design and would otherwise drive the system toward a bypass on a host whose only route is a tunnel.

Routing a provider's forwards away from tunnels SHALL be observable once per provider rather than once per flow, so a provider that resolves continuously cannot flood the log.

#### Scenario: A forward for another network extension provider avoids tunnel interfaces

- **GIVEN** DNS proxying is enabled and another network extension that is itself a resolver is running
- **WHEN** a DNS flow whose source process holds the network-extension entitlement is claimed
- **THEN** the system forwards the query without using any tunnel interface
- **AND** the flow is still claimed, so `dns_query` telemetry is emitted for it

#### Scenario: An ordinary flow honours the interface the client bound

- **GIVEN** DNS proxying is enabled and a claimed flow reports that it is bound to a specific interface
- **WHEN** the system forwards the query upstream
- **THEN** the forward leaves on the interface the flow was bound to rather than following the system default route

#### Scenario: The system's own provider takes ordinary routing

- **GIVEN** DNS proxying is enabled
- **WHEN** a DNS flow attributed to the system's own network extension is claimed
- **THEN** the system routes its forward as an ordinary flow, because the operating system already excludes the system's own outbound connections from the proxy chain

#### Scenario: Tunnel-avoiding forwards do not drive the health watchdog

- **GIVEN** DNS proxying is enabled and forwards for another provider's flows are failing because the only available route is a tunnel
- **WHEN** the forwarding-health accounting is updated
- **THEN** those outcomes are excluded, so they cannot trigger a bypass

#### Scenario: A provider routed away from tunnels is reported once

- **GIVEN** DNS proxying is enabled and another network-extension provider is resolving continuously
- **WHEN** many of its DNS flows are forwarded away from tunnel interfaces
- **THEN** the system reports that provider once rather than once per flow

### Requirement: DNS proxy reports forwarding degradation without leaving the DNS path

An enabled DNS proxy is the configured resolver for every flow it claims, and declining a flow terminates that flow rather than returning it to the operating system. The system therefore MUST NOT decline a DNS flow as a recovery action, and MUST NOT treat declining as a way to fail open. A claimed flow stays claimed.

When an upstream forward fails or reaches its deadline, the system SHALL attempt the query against another resolver from the system DNS configuration before giving up, but ONLY when the resolver the client addressed is itself part of that configuration. When the client addressed a resolver that is not in the system configuration, the system MUST NOT substitute a different one, because a substituted resolver can legitimately answer differently and would answer a question the client did not ask. An answer obtained from a substitute resolver SHALL be returned to the client as though it came from the resolver the client originally addressed.

Each forward attempt SHALL be bounded by a deadline, and the total time a client can be made to wait across all attempts SHALL be bounded. When no attempt can answer, the system SHALL release the flow so the client fails promptly rather than being pinned.

The system SHALL account upstream-forwarding outcomes over a recent window and SHALL report a sustained failure rate as degraded, and a return to working as recovered, reporting each change once rather than per forward. That report is observational: it MUST NOT change whether flows are claimed.

#### Scenario: Sustained forwarding failure is reported as degraded

- **GIVEN** DNS proxying is enabled
- **WHEN** upstream forwards fail continuously past the health threshold
- **THEN** the system reports forwarding as degraded, once rather than per forward
- **AND** the system continues to claim DNS flows

#### Scenario: A query to a system resolver is retried against another system resolver

- **GIVEN** DNS proxying is enabled and the system DNS configuration lists more than one resolver
- **WHEN** a forward to one of those resolvers fails or reaches its deadline
- **THEN** the system attempts the query against a different resolver from the system configuration
- **AND** an answer from that resolver is returned to the client as though it came from the resolver it originally addressed

#### Scenario: A query to a client chosen resolver is not retried elsewhere

- **GIVEN** DNS proxying is enabled and a client addresses a resolver that is not in the system DNS configuration
- **WHEN** the forward to that resolver fails or reaches its deadline
- **THEN** the system does not substitute a different resolver

#### Scenario: Forwarding recovery is reported

- **GIVEN** forwarding has been reported as degraded
- **WHEN** upstream forwards start succeeding again
- **THEN** the system reports forwarding as recovered, once rather than per forward
