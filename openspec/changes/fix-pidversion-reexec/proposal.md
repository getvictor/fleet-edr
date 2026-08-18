# A re-exec generation records its own kernel generation

## Why

The graph builder inherited the prior generation's `pidversion` whenever a process exec'd again on the same pid, on the stated premise that "execve does not change the kernel PID generation". The premise is false. Measured on macOS 26.6.1: a process that execl'd itself went from pidversion 2377919 to 2377920 on the same pid, and a fork-then-exec child went from 2401553 after the fork to 2401554 after the exec. Every execve increments the generation.

So every re-exec row carried the identity of the image it replaced rather than its own. That is worse than carrying no identity at all. The agent refuses a kill whose payload names a generation the pid no longer holds, and the operator UI sends whatever the row stores, so killing a re-exec'd process returned "process generation mismatch" and nothing died. The shapes that hit this are ordinary: `zsh -c '<command>'` execs the command in place with no fork, as does any wrapper script ending in `exec`.

The kill pinning that consumes the stored value (#627, #641) is newer than the last release, so the defect has not shipped to an operator yet. It is live on main, which is the cheapest moment to correct it.

## What changes

A re-exec generation records the pidversion from its own exec event. When that event carries none, the generation records none: it does not borrow the value of the generation it replaced. Nothing else about the chain changes, and the first exec after a fork keeps updating its row in place, where an absent value still leaves the fork's own value standing rather than clobbering it to NULL.

## Why NULL rather than the previous value

A stale identity and a missing identity fail differently, and the missing one fails safely. A row with no pidversion is unpinned: the kill payload omits the generation and the agent kills by pid, and flow correlation falls back to the event-time window it already uses for pre-#403 agents. A row with a stale pidversion is actively wrong: it names a generation that has not existed since the exec, so the kill is refused and identity matching for flows silently misses. Storing what we actually know, which after an exec with no reported generation is nothing, is the honest option.

## Rows already written

Existing rows keep the values they were stored with. A re-exec generation written before this change still carries its predecessor's identity, and a long-lived process keeps that value until it exits, so kills against those specific processes keep failing until they restart. History is not rewritten: the true generation of a past exec is not recoverable from anything the server holds, so a migration could only replace a wrong value with NULL, and doing that across the whole table is a large write for a population that drains on its own as processes exit. The lookup path therefore keeps disambiguating identities that match more than one generation, which is now a legacy-row concern rather than a description of kernel behavior.
