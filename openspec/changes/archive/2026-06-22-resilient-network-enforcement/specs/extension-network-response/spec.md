# Extension network response specification (delta)

## ADDED Requirements

### Requirement: Default network action is forward, deny only on explicit match

The network and DNS enforcement path SHALL forward (allow) every flow by default and SHALL deny a flow only on an explicit positive match against an active enforcement policy (a domain blocklist entry or a host-containment ruleset). Absence of policy, an unparseable payload, a telemetry failure, or a degraded upstream MUST NOT, by themselves, cause a flow to be denied. This mirrors the process-authorization model in `extension-application-control`, where no matching rule allows the exec and only an explicit BLOCK match denies it.

#### Scenario: No active policy allows resolution

- **GIVEN** the DNS proxy is enabled and no enforcement policy is active
- **WHEN** an application resolves a hostname
- **THEN** the query is forwarded to the originally-intended resolver and the response is returned

#### Scenario: A telemetry or forwarding degradation does not deny a non-matching flow

- **GIVEN** the DNS proxy is enabled and the query matches no block rule
- **WHEN** telemetry serialization fails or upstream forwarding is degraded
- **THEN** the flow is not denied as a side effect, and the fail-open path governs the outcome

### Requirement: A blocked DNS query is answered locally without upstream

When a DNS query matches an active block rule, the system SHALL answer it locally (a negative answer such as `NXDOMAIN`, or a configured sinkhole address) without contacting any upstream resolver. Enforcement of a block therefore does not depend on network reachability or on upstream-forwarding health: a proxy that cannot reach upstream can still deny a blocked domain. The system SHALL emit telemetry identifying the blocked query so the block is observable server-side.

#### Scenario: A blocked domain is denied without contacting upstream

- **GIVEN** an active block rule matches a domain
- **WHEN** an application queries that domain
- **THEN** the system returns the denial answer locally and contacts no upstream resolver
- **AND** the system emits telemetry recording the block

#### Scenario: A block is still enforced while upstream forwarding is degraded

- **GIVEN** an active block rule matches a domain AND upstream forwarding is failing for allowed traffic
- **WHEN** an application queries the blocked domain
- **THEN** the block is still enforced (the domain is denied locally) even though allowed queries cannot currently be forwarded

### Requirement: DNS proxy health watchdog with policy-aware bypass

The system SHALL monitor upstream-forwarding health and SHALL recover from sustained forwarding failure without operator intervention. When no enforcement policy is active, recovery MAY bypass DNS proxying so resolution returns to the system resolver (availability is preserved), and the system SHALL periodically attempt to restore proxying. When an enforcement policy is active, the system MUST NOT bypass in a way that lets a blocked domain resolve; it SHALL instead rebuild the proxy and continue denying blocked domains throughout recovery. A monitoring-path wedge MUST NOT require a host reboot to clear. While bypassed, the system does not see the bypassed DNS flows, so it emits no `dns_query` telemetry for them; that telemetry gap is the accepted cost of failing open (observation never gates availability) and is not a contract violation.

#### Scenario: Sustained forwarding failure with no active policy bypasses and retries

- **GIVEN** DNS proxying is enabled, no enforcement policy is active, and upstream forwarding has failed continuously past the health threshold
- **WHEN** the watchdog evaluates proxy health
- **THEN** the system bypasses DNS proxying so the system resolver handles resolution
- **AND** the system periodically attempts to restore proxying
- **AND** no `dns_query` telemetry is emitted for flows handled by the system resolver during the bypass window

#### Scenario: Sustained failure with an active blocklist does not open-bypass

- **GIVEN** DNS proxying is enabled, a domain blocklist is active, and upstream forwarding has failed past the health threshold
- **WHEN** the watchdog evaluates proxy health
- **THEN** the system does not bypass to the system resolver in a way that would let blocked domains resolve
- **AND** blocked domains remain denied while the proxy is rebuilt

### Requirement: Host network containment is declarative and survives provider restart

Host network containment (isolating a compromised endpoint from the network) SHALL be expressed as a declarative ruleset the operating system enforces (content-filter rules), persisted on device and re-applied when the extension restarts, so containment is not lost if the provider process crashes or is restarted. Containment SHALL preserve a management lifeline that permits the endpoint to keep communicating with the EDR server, so an operator can lift containment remotely. The lifeline MUST include name resolution of the EDR server: because the DNS proxy does not open-bypass while an enforcement policy is active (see the watchdog requirement), reaching a server identified only by hostname would otherwise deadlock when the proxy is wedged. The system SHALL guarantee the server resolves regardless of DNS proxy health, by a path that does not depend on the proxy forwarding successfully (for example a pinned or cached server address, or a resolution path the containment ruleset routes around the proxy). This mirrors `extension-application-control`'s persisted snapshot that is restored on extension restart.

#### Scenario: Containment persists across an extension restart

- **GIVEN** a host has been placed under network containment
- **WHEN** the network extension process restarts
- **THEN** the containment ruleset is re-applied without operator action

#### Scenario: A contained host still reaches the EDR server

- **GIVEN** a host is under network containment
- **WHEN** the agent communicates with the EDR server
- **THEN** that communication is permitted by the containment ruleset so containment can later be lifted
- **AND** the EDR server's name resolves even when the DNS proxy is degraded or wedged, by a path that does not depend on the proxy forwarding successfully, so a hostname-identified server does not deadlock the lifeline
