## MODIFIED Requirements

### Requirement: The server holds no in-process state that survives a request lifetime

The server SHALL NOT retain in-process state that outlives a single request and that a peer replica would need to serve a subsequent request correctly. Durable state SHALL live in the shared MySQL store; per-request state MAY ride in signed cookies; short-lived per-replica performance caches are permitted only when losing them on a restart is harmless. This invariant is what lets any replica behind the load balancer serve any request and lets a replica restart without customer-visible state loss. It is enforced at review time against `docs/adr/0010-stateless-server.md`. The invariant is observable end to end: state written by one replica must be servable by any other replica through the shared store.

A single sanctioned exception is the agent control-connection gateway. The gateway's only in-process state is, per connection: the live socket (keyed by host), the connection's authentication metadata (token epoch and expiry, so it can be re-checked against the revocation snapshot without a database lookup), and the set of in-flight command identifiers. It persists nothing durable: all command state remains in the shared MySQL store. The loss of a gateway or any of its connections SHALL force the affected agents to reconnect (and to fall back to the polled command path meanwhile) with no command loss, because the command rows and their statuses live in the shared store. This is a named, bounded stateful tier, not a license for request-surviving authority elsewhere.

#### Scenario: State written on one replica is served by another

- **GIVEN** durable state was written to the shared MySQL store by a request handled on one replica
- **WHEN** a later request that depends on that state is routed to a different replica
- **THEN** the second replica serves it correctly from the shared store, with no reliance on any request-surviving in-process state from the first replica

#### Scenario: Losing the gateway forces reconnect without command loss

- **GIVEN** a host holding a control connection on a gateway that then stops
- **WHEN** the gateway and its connections are lost
- **THEN** the host reconnects (to the same or another replica) and meanwhile falls back to the polled command path
- **AND** no queued command is lost, because command state was never held only in the gateway's memory
