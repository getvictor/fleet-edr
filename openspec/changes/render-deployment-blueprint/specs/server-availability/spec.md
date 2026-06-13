# Server availability: TLS termination by a front proxy delta

## ADDED Requirements

### Requirement: TLS may be terminated by a front proxy

The server SHALL terminate TLS itself by default and refuse to boot without a certificate and key (issue #140 removed the unguarded plaintext-HTTP mode). It SHALL additionally support running behind a TLS-terminating proxy (a PaaS edge, ALB, or reverse proxy) via an explicit opt-in: when the operator sets that opt-in, the server SHALL listen plaintext HTTP and SHALL NOT require certificate files, on the assertion that the proxy terminates TLS in front of it. The opt-in and server-terminated TLS SHALL be mutually exclusive so the operator cannot ambiguously configure both. When running in proxy-terminated mode the server SHALL emit a startup warning that it is serving plaintext and must not be exposed directly.

#### Scenario: Proxy-termination opt-in allows plaintext HTTP

- **GIVEN** an operator who sets the proxy-termination opt-in and supplies no certificate files
- **WHEN** the server loads its configuration
- **THEN** configuration succeeds and the server listens plaintext HTTP rather than refusing to boot

#### Scenario: Proxy flag and cert files are mutually exclusive

- **GIVEN** an operator who sets the proxy-termination opt-in AND supplies certificate files
- **WHEN** the server loads its configuration
- **THEN** configuration fails with an error that the two are mutually exclusive

#### Scenario: Mandatory TLS remains the default

- **GIVEN** an operator who sets neither the proxy-termination opt-in nor certificate files
- **WHEN** the server loads its configuration
- **THEN** configuration fails because a certificate and key are required
