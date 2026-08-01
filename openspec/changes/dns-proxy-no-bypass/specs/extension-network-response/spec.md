# extension-network-response Specification

## REMOVED Requirements

### Requirement: DNS proxy health watchdog with policy-aware bypass

**Reason**: The requirement was built on a false premise about the platform. It specified recovery from sustained forwarding failure as a bypass that "returns resolution to the system resolver". Apple documents the opposite for `NEDNSProxyProvider.handleNewFlow`: "If the proxy implementation decides to not handle the flow and instead terminate it, the subclass implementation of this method should return NO. ... In this case the flow is terminated." There is no fallback path for a DNS proxy, because the proxy is the configured resolver. Measured on a live host with a build that declined every flow: `dig` against either configured resolver returned no answer, `dscacheutil` returned zero addresses, and `ping` could not resolve a name, while every one of those queries succeeded the moment the DNS proxy configuration was disabled. The 2026-07-27 incident record agrees, showing the watchdog firing 18 times with host DNS recovering in none of those windows. The bypass therefore took host DNS down rather than failing open, which is the opposite of what the requirement promised.

**Migration**: The replacement requirement "DNS proxy reports forwarding degradation without leaving the DNS path" carries the accurate contract: the proxy stays in the path, a failing upstream is answered by retrying another system resolver, and the health accounting reports rather than acts. Tests referencing `extension-network-response/dns-proxy-health-watchdog-with-policy-aware-bypass/<scenario>` are removed along with the bypass, its latch, its backoff and its bounded probe; the surviving accounting behaviour is re-pinned under the new requirement's scenarios. Operators lose no capability, because the removed capability never worked. The policy-aware clause is subsumed: with no bypass at all, a blocked domain can never resolve via one.

## ADDED Requirements

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
