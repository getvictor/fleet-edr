# The stream carries a heartbeat, so the agent can tell forgotten from idle

## Why

Last part of issue #711. The bounded poll floor (#728) means a wedged stream no longer silences commands, and withdrawal plus ageing out (#730) means a stranded command can be withdrawn. Neither detects the split: the agent still sits on a dead stream for as long as it lasts, and every command still takes the slow path until something else knocks the connection over.

Nothing available to the agent could distinguish the two states. The gateway runs via `grpc.Server.ServeHTTP` on the shared HTTPS listener, where net/http answers the HTTP/2 keepalive PINGs itself, so a passing probe proves the transport is alive rather than that the stream is still registered for delivery. The gateway's liveness ticker only bumped server-side last-seen and sent the agent nothing.

## What changes

- A `Heartbeat` frame is added to the `ServerFrame` oneof, which the proto comment already anticipated ("leaves room for future kinds"). It carries no payload: its arrival is the signal.
- The gateway sends one on its existing liveness cadence, on the same per-connection loop that already bumps last-seen. It is dropped rather than queued when the send buffer is full, because a full buffer already demonstrates the thing the heartbeat exists to demonstrate, and a heartbeat must never displace a command.
- The agent measures silence on the stream and tears it down past a deadline. ANY frame resets the clock, heartbeat or command, because what is being measured is whether the stream is still served, not whether there is work.

The deadline defaults to four times the heartbeat cadence. Generous on purpose: a false teardown costs one reconnect, while too long a deadline is the wedge this exists to close.

## Impact

- Affected specs: `agent-control-channel`
- Affected code: `internal/control/control.proto` (and its generated code), `server/response/internal/gateway/`, `agent/controlclient/`
- Wire-compatible in both directions: an older agent ignores an unknown frame in the oneof, and a newer agent against an older server simply sees no heartbeats and falls back to the poll floor.
- Closes the last of issue #711. Surfacing undeliverable commands on host health is left as its own change: it is visibility, and the delivery failure it would surface can no longer be permanent.
