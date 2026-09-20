# Tasks

- [ ] End the `Connect` RPC with no error when the RPC's own context is done, so a client that went away records an OK span.
- [ ] Keep `Unavailable` for a locally-initiated teardown, so a still-connected client is told to reconnect.
- [ ] Carry the teardown reason on the connection and put it in the status message: replacement, token no longer valid, shutdown, dead outbound.
- [ ] Make both select cases check the RPC context, so the disconnect race cannot decide the span status.
- [ ] Tests for each of the four reasons, for the clean client disconnect, for a genuine receive failure, and for the race.
- [ ] Mutation-check the context test in the receive branch and each reason, not only the `nil` return.
- [ ] QA on the dev server with a real agent: restart it and confirm through SigNoz that its `Connect` span is OK, and that a revocation still produces an error span naming the token.
