# Tasks

- [x] Carry the set and its version on the containment command, built the same way by a change and by the catch-up.
- [x] Judge a host current only when its command carries both the state and the set, so a set change re-queues every contained host.
- [x] Read the set once per sweep, so one sweep cannot leave two hosts on different versions for no reason an operator could explain.
- [x] Pass the set through the agent without validating it, and hold it with the state so a lifeline refresh does not withdraw it.
- [x] Enforce it in the extension as part of the lifeline, dropping an entry it cannot express rather than refusing the containment.
- [x] Treat a changed set as a lifeline refresh, or the change is accepted and discarded while the command reports success.
- [x] Decode a document that predates the set, so a host upgrading while contained does not come up uncontained.
- [ ] Exercise on a live macOS VM: contain a host, reach an allowed destination, change the set, and confirm the host picks it up without being released.
