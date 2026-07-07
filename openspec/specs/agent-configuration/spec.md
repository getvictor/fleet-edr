# agent-configuration Specification

## Purpose

Defines the agent's intentionally minimal configuration surface: the small set of supported settings, their safe defaults fixed as constants, and the rule that an unrecognized or removed setting is ignored rather than failing the agent's start.

## Requirements

### Requirement: The agent configuration surface is intentionally minimal

The agent SHALL treat its upload batch size, upload interval, queue prune age, network/DNS coalescing window, and SQLite queue byte cap as fixed constants rather than environment-configurable knobs. The agent's operator-facing configuration SHALL remain limited to enrollment, connection, identity, and diagnostic settings (server URL, enroll secret, token file, server fingerprint, host id override, queue database path, XPC service names, allow-insecure, process-reconcile interval, log level, and log format), read from `/etc/fleet-edr.conf` with environment-variable overrides.

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

### Requirement: Default file locations are platform-specific

The agent SHALL resolve its default configuration-file, event-queue, and enrollment-token locations from the platform it runs on: `%ProgramData%\FleetEDR\` on Windows, and `/etc/fleet-edr.conf` plus `/var/db/fleet-edr/` on macOS and Linux. An operator MAY still override any location through the existing environment variables; the platform default applies only when the override is unset.

#### Scenario: The agent resolves platform-appropriate default paths

- **GIVEN** an agent started with no path-override environment variables
- **WHEN** it resolves its default configuration
- **THEN** the configuration-file, event-queue, and enrollment-token paths are the platform's default locations
