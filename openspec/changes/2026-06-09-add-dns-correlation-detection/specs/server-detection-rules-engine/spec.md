# Server detection rules engine: DNS correlation delta

## ADDED Requirements

### Requirement: DNS-correlated C2 beacon detection

The system SHALL register a `dns_c2_beacon` rule that fires when a suspicious process resolves a domain and then
connects to the resolved address, correlating all three telemetry streams. The rule MUST require, for a single
originating process: a `dns_query` event carrying one or more `response_addresses`, and a subsequent `network_connect`
event whose `remote_address` is one of those `response_addresses`, both within a bounded time window for that process.
Address matching MUST be performed on parsed/normalized IP values (not raw strings) so that equivalent IPv6 forms
compare equal. When several `dns_query` events for the process match the connection's `remote_address`, the rule MUST
select the most recent matching query (deterministic tie-break by query name) for finding attribution.

The rule MUST gate on a suspicion signal derived from the originating process's exec context (for example an exec from a
temporary or world-writable path, or a script interpreter with a non-interactive parent) so that ordinary browser
traffic that resolves and connects to a domain does NOT fire. When the resolved domain also matches a domain-anomaly
signal (a high-entropy or algorithmically-generated name), the rule MAY raise the finding severity and MUST add the
`T1568.002` technique.

A firing alert SHALL cite the `exec`, `dns_query`, and `network_connect` events that compose the chain, and SHALL be
attributed to the originating process so the engine's per-process dedup collapses repeated beacons into a single alert.
The rule MUST hold no state between batches; the correlation is performed by retrospective graph reads.

#### Scenario: A suspicious process resolves a domain and connects to the resolved address

- **GIVEN** a process exec'd from a temporary path that issued a `dns_query` for a high-entropy domain whose
  `response_addresses` include `203.0.113.10`
- **WHEN** a `network_connect` event for the same process to `remote_address` `203.0.113.10` is evaluated, within the
  correlation window
- **THEN** the engine produces one `dns_c2_beacon` finding
- **AND** the finding cites the originating `exec`, the `dns_query`, and the `network_connect` event identifiers
- **AND** the finding is attributed to the originating process
- **AND** the finding carries the `T1071.004` technique, plus `T1568.002` because the domain tripped the anomaly signal

#### Scenario: A browser resolving and connecting to an ordinary domain does not fire

- **GIVEN** a browser process that issued a `dns_query` for an ordinary domain and connected to one of its
  `response_addresses`
- **WHEN** the `network_connect` event is evaluated
- **THEN** the engine produces no `dns_c2_beacon` finding, because the originating process does not satisfy the
  suspicious-exec-context gate

#### Scenario: A suspicious process that connects to an address it never resolved does not fire

- **GIVEN** a process exec'd from a temporary path that issued a `dns_query` resolving to `203.0.113.10`
- **WHEN** the same process emits a `network_connect` to `198.51.100.7`, an address that appears in none of its
  `dns_query` `response_addresses`
- **THEN** the engine produces no `dns_c2_beacon` finding, because the resolve-then-connect join is not satisfied

## MODIFIED Requirements

### Requirement: Registered rule catalog

The system SHALL register the following named rules at startup so each becomes evaluable against every batch:
`suspicious_exec`, `shell_from_office`, `osascript_network_exec`, `persistence_launchagent`, `dyld_insert`,
`credential_keychain_dump`, `privilege_launchd_plist_write`, `sudoers_tamper`, and `dns_c2_beacon`.

#### Scenario: The engine reports its rule catalog

- **GIVEN** a running detection engine in its default configuration
- **WHEN** an operator inspects the catalog of registered rules
- **THEN** the catalog includes `suspicious_exec`, `shell_from_office`, `osascript_network_exec`,
  `persistence_launchagent`, `dyld_insert`, `credential_keychain_dump`, `privilege_launchd_plist_write`,
  `sudoers_tamper`, and `dns_c2_beacon`
