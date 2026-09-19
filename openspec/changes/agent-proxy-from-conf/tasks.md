# Tasks

- [x] Read `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` through the agent's layered configuration, in either case, with the environment still winning.
- [x] Build the chooser with `x/net/http/httpproxy` so the scheme and `NO_PROXY` rules match what operators expect.
- [x] Use it for the shared agent transport, enrollment, the containment lifeline target, and the control channel.
- [x] Drop `controlDialOptions`' redundant proxy parameter so there is one source for the decision.
- [x] Tests for the configuration layer and for each of the four wirings; mutation-check every wiring, not just the chooser.
- [x] Document reaching the server through a proxy in `docs/operations.md`, which had nothing on it.
- [ ] Re-run the #1110 VM QA with the proxy in `/etc/fleet-edr.conf` rather than the plist, which is what originally failed.
