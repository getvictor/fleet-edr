# Tasks

- [x] Store the reachable-address set as one versioned row, seeded empty, replaced whole under its own lock.
- [x] Validate a replacement: canonical destinations, a floor on range breadth, one entry per destination, a cap on the set, and a refusal that names the entry at fault.
- [x] Promote the address parser the trusted-proxy list already had, rather than writing a second one that disagrees with it about a bare IPv6 literal.
- [x] Require a reason and audit the replacement with what it added and removed.
- [x] Gate reading and replacing on their own permissions, with the write reauthenticated like the host commands.
- [x] Serve the read and the replacement, reporting each refusal as its own code.
- [ ] Deliver the set with each host's containment state, and enforce it on the host (next change).
- [ ] Edit the set in the console (the change after that).
