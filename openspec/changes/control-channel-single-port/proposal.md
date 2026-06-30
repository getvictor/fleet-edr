# Serve the agent control channel on the main port

## Why

The push control channel (`push-command-channel`) shipped on its own gRPC listener, gated by an `EDR_CONTROL_ADDR` bind address on the server and a matching dial address on the agent. That is more deployment surface than the pilot envelope needs and more than the established endpoint products expose: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, and Carbon Black all run a single agent-initiated outbound connection on one port, always on, with the channel sharing the address the agent already uses. A second port means a second firewall rule, a second proxy route, and a second thing an operator can misconfigure, for no capability gain.

This change folds the control channel onto the server's existing HTTPS listener and derives the agent's endpoint from its server URL, so there is nothing extra to configure on either side. The channel is always on; the short-poll remains the automatic fallback. The control channel was still off by default and unreleased, so this is an internal refinement with no migration for any deployment.

## What changes

- **One port.** The control-channel gRPC gateway is multiplexed onto the same listener and port as the REST API and UI. A single native HTTP/2 server dispatches by content-type: `application/grpc` to the gateway (via `grpc.Server.ServeHTTP`), everything else to the REST/UI handler. TLS is terminated once at that listener (or by the front proxy), so the gateway runs without its own transport credentials.
- **No control-channel configuration.** `EDR_CONTROL_ADDR` is removed from both the server and the agent. The server needs no separate bind address; the agent derives the control endpoint from `EDR_SERVER_URL` (same host and port, same transport security). A still-set, no-longer-recognized control-address variable is inert.
- **Always on, poll is the floor.** The agent attempts the control channel whenever a server URL and host identity are configured, with no enabling flag and no disabling flag. If the stream cannot connect or drops, the `GET /api/commands` short-poll continues to serve commands.

## Affected specs

- `server-configuration`: ADDED requirement that the control channel shares the server's single listener (multiplexed by content-type, no separate bind address). The existing "an environment variable the server no longer recognizes SHALL be inert" requirement already covers a still-set `EDR_CONTROL_ADDR`.
- `agent-control-channel`: ADDED requirement that the agent derives the control endpoint from its server URL and keeps the channel always on with the short-poll as the fallback. The persistent-connection, auth, delivery, outcome, liveness, and revocation requirements from `push-command-channel` are unchanged.
