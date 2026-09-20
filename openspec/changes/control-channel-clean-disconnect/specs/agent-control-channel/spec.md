## ADDED Requirements

### Requirement: How a connection ended is what its telemetry reports

The system SHALL end the control RPC with no error when the connection ended because the client went away, so the recorded span for that connection is successful. An agent restart, a suspended host, and a dropped network link are the ordinary way a long-lived control connection ends, and recording them as faults leaves the operation permanently error-coloured, which hides the faults that are real.

The system SHALL end the RPC with a retryable non-OK status when the server itself tore the connection down, because the client is still attached and that status is what tells it to reconnect. Those SHALL remain error spans: a connection the server ended is the case an operator is looking for.

The status SHALL identify which teardown it was. Replacement by a newer connection from the same host, a token that is no longer valid, gateway shutdown, and an outbound that can no longer carry frames are distinct operational events, and an operator asking why a host's channel dropped SHALL be able to tell them apart from the recorded connection alone.

A failure of the receive loop itself SHALL still end the RPC with that error.

The verdict SHALL NOT depend on which of the concurrent end conditions is observed first. A client that goes away both cancels the RPC context and fails the pending receive, so the outcome MUST be decided by whether the client is gone rather than by whichever signal arrived first.

Reporting an ordinary disconnect as successful SHALL NOT change what the agent does: it reconnects on a clean end of stream exactly as it does on a retryable status, through the same backoff.

#### Scenario: A client that disconnects ends its connection cleanly

- **GIVEN** a host holding an open control connection
- **WHEN** the agent restarts, sleeps, or loses its network, so the RPC's context is cancelled
- **THEN** the server ends the RPC with no error and the connection's span is recorded as successful
- **AND** the agent reconnects as it does from any other disconnect

#### Scenario: A server teardown still tells the client to reconnect

- **GIVEN** a host holding an open control connection that the server ends, because a newer connection replaced it, its token is no longer valid, the gateway is shutting down, or its outbound has failed
- **WHEN** the RPC ends
- **THEN** the client receives a retryable status and reconnects
- **AND** the recorded status identifies which of those it was

#### Scenario: A receive failure is still recorded as a failure

- **GIVEN** a connected host whose stream fails while the client is still attached
- **WHEN** the receive loop returns that failure
- **THEN** the RPC ends with it and the connection is recorded as failed
