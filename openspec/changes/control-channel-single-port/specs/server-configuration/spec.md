## ADDED Requirements

### Requirement: The agent control channel shares the main server listener

The server SHALL serve the agent control-channel gRPC gateway on the same listener and port as the REST API and the UI, multiplexed by request content-type: gRPC requests (HTTP/2 with an `application/grpc` content type, which gRPC requires) are dispatched to the control gateway, and all other requests to the REST/UI handler. The server SHALL NOT expose a separate bind address for the control channel; there is no control-channel address environment variable. A deployment that still sets a no-longer-recognized control-channel address variable SHALL find it inert: boot succeeds and behavior is unchanged. When the server terminates TLS itself, gRPC and REST SHALL both be served over the single TLS listener using ALPN-negotiated HTTP/2; in the TLS-terminated-by-proxy mode the server SHALL also accept cleartext HTTP/2 (h2c), so a front proxy can forward the control stream to the same upstream as REST.

#### Scenario: gRPC and REST share one port

- **GIVEN** a server listening on a single address, whether it terminates TLS itself or runs behind a TLS-terminating proxy
- **WHEN** an agent opens the control-channel gRPC stream and a client issues a REST request to the same server
- **THEN** both are served on the same host and port, separated by request content-type
- **AND** no separate control-channel bind address is configured on the server
