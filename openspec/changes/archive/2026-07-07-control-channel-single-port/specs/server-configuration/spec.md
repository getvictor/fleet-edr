## ADDED Requirements

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
