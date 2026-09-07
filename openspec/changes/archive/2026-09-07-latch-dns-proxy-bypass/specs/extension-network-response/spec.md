# extension-network-response Specification

## MODIFIED Requirements

### Requirement: DNS proxy health watchdog with policy-aware bypass

The system SHALL monitor upstream-forwarding health and SHALL recover from sustained forwarding failure without operator intervention. When no enforcement policy is active, recovery MAY bypass DNS proxying so resolution returns to the system resolver (availability is preserved), and the system SHALL periodically attempt to restore proxying. When an enforcement policy is active, the system MUST NOT bypass in a way that lets a blocked domain resolve; it SHALL instead rebuild the proxy and continue denying blocked domains throughout recovery. A monitoring-path wedge MUST NOT require a host reboot to clear. While bypassed, the system does not see the bypassed DNS flows, so it emits no `dns_query` telemetry for them; that telemetry gap is the accepted cost of failing open (observation never gates availability) and is not a contract violation.

A bypass SHALL hold for a bounded interval before the system attempts to restore proxying, so that a host with a wedged upstream resolves names for the whole interval rather than oscillating between bypassing and re-claiming. Each consecutive restore attempt that finds the upstream still failing SHALL extend the hold up to a cap; a restore attempt that finds the upstream healthy SHALL resume proxying and reset the hold to its base interval, so a transient failure never leaves the system bypassed indefinitely. A restore attempt SHALL claim no more than a bounded number of DNS flows, and SHALL bypass every other flow arriving while it is in progress, so that probing the upstream cannot stall the host's live query traffic. A restore attempt that reaches its own deadline without enough outcomes to judge the upstream is inconclusive and SHALL re-arm the hold without extending it, so an idle host is not driven to the cap by absence of traffic. Entering a bypass, starting a restore attempt, and resuming proxying SHALL each be individually observable, so that a single sustained bypass is distinguishable from repeated re-trips.

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

#### Scenario: A bypass holds before the upstream is probed again

- **GIVEN** the watchdog has bypassed DNS proxying after sustained forwarding failure
- **WHEN** DNS flows arrive before the hold interval has elapsed
- **THEN** every one of them is bypassed to the system resolver
- **AND** the system does not attempt to restore proxying until the hold interval has elapsed

#### Scenario: A restore attempt claims only a bounded number of flows

- **GIVEN** the watchdog has bypassed DNS proxying and the hold interval has elapsed
- **WHEN** more DNS flows arrive than the restore attempt's claim budget
- **THEN** the system claims at most the claim budget of them
- **AND** every further flow arriving during the restore attempt is bypassed to the system resolver

#### Scenario: Consecutive failed restore attempts extend the hold up to a cap

- **GIVEN** the watchdog has bypassed DNS proxying and the upstream remains wedged
- **WHEN** successive restore attempts each find forwarding still failing
- **THEN** each subsequent hold interval is longer than the one before it
- **AND** the hold interval stops growing once it reaches the cap

#### Scenario: A healthy restore attempt resumes proxying and resets the hold

- **GIVEN** the watchdog has bypassed DNS proxying and extended the hold across several failed restore attempts
- **WHEN** a restore attempt finds upstream forwarding healthy
- **THEN** the system resumes claiming DNS flows and emitting `dns_query` telemetry
- **AND** a subsequent bypass starts again from the base hold interval

#### Scenario: An inconclusive restore attempt re-arms without extending the hold

- **GIVEN** the watchdog has started a restore attempt
- **WHEN** the attempt reaches its deadline without enough forwarding outcomes to judge the upstream
- **THEN** the system re-arms the bypass at the same hold interval it last used
- **AND** the hold interval is not extended by the inconclusive attempt
