# extension-network-response Specification

## Purpose

Defines the network extension's DNS-forwarding resilience: a health watchdog that monitors upstream-forwarding health and recovers from sustained failure without operator intervention. When no enforcement policy is active it fails open (resolution returns to the system resolver, availability preserved) and periodically attempts to restore proxying; when a policy is active it never bypasses in a way that would let a blocked domain resolve.

## Requirements

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
