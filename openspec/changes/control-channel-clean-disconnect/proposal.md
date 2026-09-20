# An ordinary control-channel disconnect is not a failure

Issue #1124. The gateway ends the `Connect` RPC with `Unavailable` whenever the connection's context is done, and a client that went away cancels that context. So an agent restart, a closed laptop lid, or a dropped Wi-Fi link is recorded exactly like a fault: otelgrpc's stats handler reads the non-OK status and colours the span Error.

Measured on edr-dev during the v0.6 QA. All three `Connect` spans in the window were errors, all with `statusMessage="control connection closed"`, and all three were agent restarts I performed myself. The stream is long-lived, so each span's duration is the connection's lifetime, which makes the latency and error-rate panels for that operation report the fleet's uptime rather than its health.

The effect compounds with fleet size. Every host disconnects routinely, so on a real deployment this operation is permanently error-coloured and a genuine fault on the control path is indistinguishable from the background.

## What changes

- **A client that went away ends the RPC cleanly.** When the RPC's own context is done there is nobody left to return a status to, so the handler returns no error and the span is OK. This is the overwhelming majority of disconnects.
- **A locally-initiated teardown still returns `Unavailable`.** There the client is still connected and the status is what tells it to reconnect promptly, so it stays, and so does the error span: those are the rare ones worth looking at.
- **The status says which teardown it was.** Replacement by a newer connection from the same host, a token that is no longer valid, gateway shutdown, and a dead outbound are four different operational stories, and the operator asking why a host's channel dropped was previously given one sentence covering all of them. The reason rides the status message, which is the `statusMessage` a trace query already filters on, so it needs no new instrumentation.
- **A genuine receive-loop failure is unchanged.** It still returns its error and still produces an error span.
- **Both ends of the race reach the same verdict.** A client disconnect cancels the context and fails the pending `Recv` at the same time, so either select case can win. Both now check whether the RPC's context is done, so which one fires does not decide the span's colour.

## Why not just suppress the span

Because the span is the right record of a long-lived stream; its status was the wrong part. Dropping or sampling `Connect` out would also lose the teardowns that matter, and the duration (how long the host held the channel) is worth keeping.

## Decided here: what telemetry separates

The issue asked whether revocation and expiry should be separable from an ordinary replacement. They are, and they say so in the status message. Revocation is NOT separated from expiry: the verifier returns one `ErrInvalidToken` for unknown, revoked, expired and malformed tokens, and inventing a distinction the verifier does not draw would put a guess in the telemetry. "Token no longer valid" is what the server actually knows.

## Out of scope

- Any change to what the agent does on a disconnect. It reconnects on `EOF` exactly as it does on `Unavailable`, through the same backoff, which is why this is safe to change at all.
- Separating a revoked token from an expired one, which needs a verifier that distinguishes them.
- The span's duration semantics for long-lived streams.
