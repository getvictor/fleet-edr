# The command poll is a bounded floor, not a belief-gated fallback

## Why

First half of issue #711. An agent can hold a control-channel stream the server no longer has, and because the poll was gated on the agent's own belief about that stream, the agent then stopped asking for work permanently. Every health signal stayed green.

Observed on dogfood: a `kill_process` sat `pending` for over 75 minutes against a host reporting `overall_status: healthy` with 49.6M events flowing and its host token refreshing on schedule. The agent log had no executor line for it at all, and no `control channel disconnected` since two days earlier.

Nothing was positioned to break the tie. The agent marks itself connected as soon as `Connect()` returns and only clears it when the receive loop returns, and that loop blocks in `Recv()`. The gRPC keepalive cannot help, because the gateway runs via `grpc.Server.ServeHTTP` on the shared HTTPS listener where net/http answers the PINGs itself: a passing probe proves the HTTP/2 link is alive, not that the stream is registered for delivery. The gateway's own liveness ticker only bumps server-side last-seen and sends the agent nothing.

## What changes

The poll defers to the stream for at most a bounded floor interval (2 minutes) rather than for as long as the agent believes the stream is up. A wedged stream now degrades to slow polling instead of silence.

This is deliberately the blunt half of the fix. It does not detect the split, it removes the split's ability to be permanent, and it does so without depending on any signal the wedge itself compromises. Detecting the split quickly needs a server-originated frame on the stream and a receive deadline against it, which spans both sides and is worth its own change.

Redundant polls are safe: the server answers with pending commands only, and the durable ledger shared with the control client already prevents a command delivered by the stream from being executed twice (issue #558).

## Impact

- Affected specs: `agent-control-channel`
- Affected code: `agent/commander/commander.go`
- Still to do for #711: fast detection of the split (server heartbeat plus receive deadline), an operator cancel route, a pending-command TTL, and surfacing undeliverable commands on host health.
