# Tasks

- [ ] One list of the proxy schemes the agent speaks, in `agent/config`, asked by the control channel's tunnel dispatch instead of its own copy.
- [ ] Drop a setting whose scheme is unsupported while loading, recording it so startup can report it.
- [ ] Refuse one in `ProxyFunc` as well, so a configuration built by hand cannot hand a dialer a proxy the agent cannot speak.
- [ ] Report the refusal once at startup, naming the setting and the scheme.
- [ ] Tests: no bytes to an unsupported proxy through the agent's own resolution, the lifeline target falling back to the server, supported schemes unchanged, and a value written without a scheme still read as HTTP.
- [ ] Mutation-check the refusal at both points and the shared list, not only the loader.
- [ ] Update `docs/operations.md`, which currently tells operators an unsupported proxy is dialed as before.
- [ ] Re-run the #1110 VM case that found this: an unsupported scheme carrying credentials must leave the listener with nothing.
