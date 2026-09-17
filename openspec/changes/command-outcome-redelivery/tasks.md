# Tasks

- [x] Store: list a host's commands that are acked, have no outcome, and were acked inside the redelivery window.
- [x] Gateway: offer those to a connected host alongside its pending backlog, on connect and on the watch tick.
- [x] Spec: the control channel's at-least-once requirement covers a command that has already been acked.
- [x] Dev server and VM: an acked command with a lost outcome reaches its terminal status, and the side effect is not repeated.
