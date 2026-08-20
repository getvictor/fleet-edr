# Tasks

- [x] Add the `Heartbeat` frame to the `ServerFrame` oneof and regenerate
- [x] Send it from the gateway's existing per-connection liveness loop, dropping rather than queuing when the buffer is full
- [x] Measure silence on the agent's receive loop and tear the stream down past the deadline
- [x] Tests both ways: a silent stream reconnects, a heartbeating idle stream does not, and the gateway actually sends one
