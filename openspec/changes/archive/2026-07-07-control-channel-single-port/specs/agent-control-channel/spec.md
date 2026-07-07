## ADDED Requirements

### Requirement: The agent derives the control endpoint from its server URL

The agent SHALL derive the control-channel endpoint from its configured server URL, dialing the same host and port it uses for the REST API, over the same transport security: the pinned-TLS configuration for an `https` server URL, and cleartext for an `http` server URL (the development / proxy-terminated posture). The agent SHALL NOT require a separate control-channel address. The agent SHALL attempt the control channel whenever a server URL and a host identity are configured, without a separate enabling flag; when the stream cannot be established or is lost, the agent SHALL continue to serve commands over the `GET /api/commands` short-poll, which remains the fallback floor.

#### Scenario: The control endpoint is derived from the server URL

- **GIVEN** an agent configured with a server URL and no separate control-channel address
- **WHEN** it opens the control channel
- **THEN** it dials the same host and port as the server URL, with the same transport security
- **AND** an `https` URL dials with the agent's pinned-TLS configuration while an `http` URL dials cleartext
