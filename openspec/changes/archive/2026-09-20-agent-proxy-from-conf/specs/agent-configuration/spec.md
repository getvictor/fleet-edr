## MODIFIED Requirements

### Requirement: The agent configuration surface is intentionally minimal

The agent SHALL treat its upload batch size, upload interval, queue prune age, network/DNS coalescing window, and SQLite queue byte cap as fixed constants rather than environment-configurable knobs. The agent's operator-facing configuration SHALL remain limited to enrollment, connection, identity, and diagnostic settings (server URL, enroll secret, token file, server fingerprint, host id override, queue database path, XPC service names, allow-insecure, process-reconcile interval, log level, log format, and the outbound proxy), read from `/etc/fleet-edr.conf` with environment-variable overrides.

The outbound proxy SHALL be read from that same layered configuration, under the conventional `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` names in either case, and SHALL apply to every connection the agent makes to the server: enrollment, event uploads, command polling, token refresh, the address the containment lifeline pins, and the control channel. Reading it from the process environment alone SHALL NOT be sufficient, because the conf file is where operators are told the agent's settings live, so a proxy configured there would otherwise be silently ignored.

It SHALL apply to all of those or none. A proxy covering only part of the agent's traffic is worse than none: the covered part hides the uncovered part, and the containment lifeline would pin an address the rest of the agent was not dialing.

The fixed queue byte cap SHALL still be enforced at its constant value: the cap is not configurable but remains active, dropping over-cap rows and counting them. An environment variable the agent no longer recognizes SHALL be inert: its presence MUST NOT fail startup and MUST NOT change behavior.

#### Scenario: A removed tuning variable is ignored at startup

- **GIVEN** a host whose conf file or environment sets a no-longer-recognized variable (for example `EDR_BATCH_SIZE` or `EDR_NETWORK_COALESCE_WINDOW`)
- **WHEN** the agent loads its configuration
- **THEN** it starts successfully using the fixed default
- **AND** the variable has no effect on behavior

#### Scenario: The queue byte cap remains enforced though not configurable

- **GIVEN** the agent's SQLite queue reaches its fixed byte cap
- **WHEN** new events are enqueued
- **THEN** over-cap rows are dropped and counted in the queue-dropped metric
- **AND** no configuration is required or accepted to change the cap

#### Scenario: A proxy set in the conf file is used

- **GIVEN** a host whose `/etc/fleet-edr.conf` sets a proxy and whose process environment sets none
- **WHEN** the agent loads its configuration and connects to the server
- **THEN** its enrollment, uploads, command polling, lifeline target and control channel all go through that proxy
- **AND** a proxy set in the process environment instead overrides the file, as every other setting does
