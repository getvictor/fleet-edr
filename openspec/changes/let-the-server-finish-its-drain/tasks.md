# Tasks

- [ ] Declare `stop_grace_period` on every compose service that runs the server: prod, quickstart, demo, and the multi-replica stack.
- [ ] A test that fails when a shipped compose grants less than the drain window plus the shutdown deadline, reading both from the Go constants rather than restating them.
- [ ] Correct the rolling-upgrade procedure, which tells operators Compose waits for the drain when by default it does not.
- [ ] Say what the equivalent is for deployments this project does not ship: Kubernetes and systemd.
- [ ] Mutation-check the test itself: a compose with no allowance, and one with too little, must both fail it.
- [ ] Fix the lane's restart script, which waits ten seconds for a thirty-second drain and is how this was found.
