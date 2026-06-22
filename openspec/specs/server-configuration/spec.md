# server-configuration Specification

## Purpose

Defines the server's intentionally minimal configuration surface: the supported environment variables (including the single `EDR_DSN` database path and a TLS 1.3 floor), their safe defaults fixed as constants, and the rule that a removed or unrecognized variable is ignored rather than failing boot, while every security, compliance, and documented operational lever is retained.

## Requirements

### Requirement: The server configuration surface is intentionally minimal

The server SHALL expose only deployment-shape and security/policy configuration as environment variables, and SHALL treat internal operational tuning as fixed constants rather than operator knobs. Specifically, the process-graph tick interval and batch size, the retention sweep interval, the stale-process TTL and its sweep interval, the host-token lifetime, the read-audit sampling rate, the async-audit-writer queue capacity, the OIDC scope set, the OIDC state-cookie TTL, and the break-glass relying-party display name SHALL be fixed constants compiled into the server, not environment-configurable.

The database connection SHALL be configured only as a single DSN (`EDR_DSN`, or `EDR_DSN_FILE` for a docker-secret mount); the server SHALL NOT compose a DSN from discrete `EDR_MYSQL_*` parts.

The server SHALL require TLS 1.3 as its unconditional minimum protocol version when it terminates TLS itself; there SHALL be no operator opt-in to a lower version.

An environment variable that the server no longer recognizes SHALL be inert: its presence MUST NOT fail boot and MUST NOT change behavior.

#### Scenario: A removed tuning variable is ignored at boot

- **GIVEN** a deployment that sets a no-longer-recognized variable (for example `EDR_PROCESS_INTERVAL` or `EDR_HOST_TOKEN_LIFETIME`)
- **WHEN** the server boots with an otherwise valid configuration
- **THEN** it loads successfully using the fixed default
- **AND** the variable has no effect on behavior

#### Scenario: The database requires a single DSN

- **GIVEN** a configuration with no `EDR_DSN` set
- **WHEN** the server loads its configuration
- **THEN** it refuses to start with an error stating `EDR_DSN` is required
- **AND** discrete `EDR_MYSQL_*` parts do not satisfy the requirement

#### Scenario: TLS 1.2 cannot be enabled

- **GIVEN** the server terminates TLS itself with a valid certificate and key
- **WHEN** it configures its TLS listener
- **THEN** the minimum accepted protocol version is TLS 1.3
- **AND** there is no configuration that lowers it to TLS 1.2
