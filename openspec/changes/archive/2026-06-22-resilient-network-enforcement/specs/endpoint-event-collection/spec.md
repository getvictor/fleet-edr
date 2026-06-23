# Endpoint event collection specification (delta)

## MODIFIED Requirements

### Requirement: DNS query capture

When DNS proxying is enabled, the system SHALL emit a `dns_query` event for each DNS query seen by the DNS proxy and a follow-on `dns_query` event carrying the resolved addresses when the upstream resolver replies. DNS proxying is opt-in (see the host-app extension manager capability), so a host with the DNS proxy disabled emits no `dns_query` events at all and that absence is not a contract violation. The `dns_query` payload SHALL additionally carry the querying process's kernel PID generation (`pidversion`, read from the flow's audit token) when it is available. The `pidversion` field is optional: when the flow carries no usable audit token the event is still emitted without it. Capture failures MUST NOT prevent the query or its response from being forwarded to the originally-intended resolver.

Because an enabled DNS proxy is the sole resolver for every claimed flow, forwarding itself MUST be resilient: each upstream forward SHALL be bounded by a deadline, and on forward failure or deadline expiry for a query that no active enforcement policy blocks the proxy SHALL fail open by releasing the flow cleanly rather than leaving the client's resolution hung. The proxy MUST NOT pin a flow indefinitely waiting on an upstream that never answers. Telemetry remains strictly best-effort and never gates forwarding or the fail-open path. Health-driven recovery from sustained forwarding failure is specified by the network-response capability.

#### Scenario: An application resolves a hostname over UDP

- **GIVEN** DNS proxying is enabled
- **WHEN** an application sends a UDP DNS query for a hostname
- **THEN** the system forwards the query unchanged to the originally-intended resolver
- **AND** the system emits a `dns_query` event identifying the source PID, source path, effective UID, query name, query type, and protocol (`udp`)
- **AND** the payload includes the source process's `pidversion` when the flow's audit token is available
- **AND** when the resolver replies with one or more addresses the system emits a follow-on `dns_query` event carrying the resolved addresses in `response_addresses`

#### Scenario: A DNS query that cannot be parsed is still forwarded

- **GIVEN** DNS proxying is enabled
- **WHEN** an application sends a DNS query whose payload the proxy cannot parse for telemetry
- **THEN** the system forwards the query to the originally-intended resolver
- **AND** the system does not emit a `dns_query` event for the unparsed payload

#### Scenario: An upstream that never replies does not hang resolution forever

- **GIVEN** DNS proxying is enabled and no active enforcement policy blocks the query
- **WHEN** an application sends a DNS query and the upstream resolver does not answer within the forward deadline
- **THEN** the proxy releases the flow rather than holding it open indefinitely
- **AND** the client's resolution is free to proceed (retry or roll over to another resolver) instead of being pinned by the proxy
- **AND** any telemetry for the query is best-effort and its absence is not a contract violation
