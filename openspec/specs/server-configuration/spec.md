# server-configuration Specification

## Purpose

Defines the server's intentionally minimal configuration surface: the supported environment variables (including the single `EDR_DSN` database path and a TLS 1.3 floor), their safe defaults fixed as constants, and the rule that a removed or unrecognized variable is ignored rather than failing boot, while every security, compliance, and documented operational lever is retained.

## Requirements

### Requirement: The server configuration surface is intentionally minimal

The server SHALL expose only deployment-shape and security/policy configuration as environment variables, and SHALL treat internal operational tuning as fixed constants rather than operator knobs. Specifically, the process-graph tick interval and batch size, the retention sweep interval, the stale-process TTL and its sweep interval, the host-token lifetime, the read-audit sampling rate, the async-audit-writer queue capacity, the OIDC scope set, the OIDC state-cookie TTL, the break-glass relying-party display name, and the control-channel command-watch interval SHALL be fixed constants compiled into the server, not environment-configurable.

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

#### Scenario: The command-watch interval is not an operator knob

- **GIVEN** a deployment that sets an environment variable attempting to override the control-channel command-watch interval
- **WHEN** the server boots
- **THEN** the variable is inert and the gateway watches on its fixed compiled interval

### Requirement: The agent control channel shares the main server listener

The server SHALL serve the agent control-channel gRPC gateway on the same listener and port as the REST API and the UI, multiplexed by request content-type: gRPC requests (HTTP/2 with an `application/grpc` content type, which gRPC requires) are dispatched to the control gateway, and all other requests to the REST/UI handler. The server SHALL NOT expose a separate bind address for the control channel; there is no control-channel address environment variable. A deployment that still sets a no-longer-recognized control-channel address variable SHALL find it inert: boot succeeds and behavior is unchanged. When the server terminates TLS itself, gRPC and REST SHALL both be served over the single TLS listener using ALPN-negotiated HTTP/2; in the TLS-terminated-by-proxy mode the server SHALL also accept cleartext HTTP/2 (h2c), so a front proxy can forward the control stream to the same upstream as REST. Because the control channel is a long-lived stream sharing the REST server, which enforces per-request read and write timeouts, the server SHALL clear those per-stream deadlines for the control-channel request so the stream is not torn down when a REST timeout elapses; the REST and UI surface keeps its timeouts.

#### Scenario: gRPC and REST share one port

- **GIVEN** a server listening on a single address, whether it terminates TLS itself or runs behind a TLS-terminating proxy
- **WHEN** an agent opens the control-channel gRPC stream and a client issues a REST request to the same server
- **THEN** both are served on the same host and port, separated by request content-type
- **AND** no separate control-channel bind address is configured on the server

#### Scenario: Control stream not bounded by REST timeouts

- **GIVEN** the shared listener enforces the REST server's per-request read and write timeouts
- **WHEN** an agent holds the long-lived control-channel stream open past those timeouts
- **THEN** the server SHALL NOT tear the stream down when a REST timeout elapses, because the read and write deadlines are cleared for the control stream
- **AND** the stream stays up to deliver a later command, while the REST and UI surface keeps its timeouts unchanged
