# A re-exec generation records its own kernel generation

## Why

The graph builder inherited the prior generation's `pidversion` whenever a process exec'd again on the same pid, on the stated premise that "execve does not change the kernel PID generation". The premise is false. Measured on macOS 26.6.1: a process that execl'd itself went from pidversion 2377919 to 2377920 on the same pid, and a fork-then-exec child went from 2401553 after the fork to 2401554 after the exec. Every execve increments the generation.

So every re-exec row carried the identity of the image it replaced rather than its own. That is worse than carrying no identity at all. The agent refuses a kill whose payload names a generation the pid no longer holds, and the operator UI sends whatever the row stores, so killing a re-exec'd process returned "process generation mismatch" and nothing died. The shapes that hit this are ordinary: `zsh -c '<command>'` execs the command in place with no fork, as does any wrapper script ending in `exec`.

The kill pinning that consumes the stored value (#627, #641) is newer than the last release, so the defect has not shipped to an operator yet. It is live on main, which is the cheapest moment to correct it.

## What changes

A re-exec generation records the pidversion from its own exec event instead of the one it replaced. When that event carries no pidversion at all, the generation keeps the replaced value. Nothing else about the chain changes, and this is now the same rule the first exec after a fork already applied, where an absent value leaves the fork's own value standing rather than clobbering it to NULL.

## Why the previous value rather than NULL when the event reports none

The two failure modes are not what they look like from the server alone. The agent does not learn generations from the database; it learns them from the same event stream, and it records one only for an envelope that carries one. So an exec event with no pidversion leaves the agent holding the replaced generation too, and keeping that value server-side means the two sides agree: a kill on the current image is allowed, and a kill aimed at a recycled pid is still refused, because a recycled pid arrives with a distant generation. Recording none instead drops the pin: the payload omits the generation, the agent skips the check entirely, and a pid recycled between selecting the process and the command reaching the host is killed unchallenged. That is the outcome generation pinning exists to prevent, so the fall-back keeps the pin. It costs nothing in the normal case, where the exec event does report a generation and that value wins.

## Rows already written

Existing rows keep the values they were stored with. A re-exec generation written before this change still carries its predecessor's identity, and a long-lived process keeps that value until it exits, so kills against those specific processes keep failing until they restart. History is not rewritten: the true generation of a past exec is not recoverable from anything the server holds, so a migration could only overwrite a wrong value with a guess, and doing that across the whole table is a large write for a population that drains on its own as processes exit. The lookup path therefore keeps disambiguating identities that match more than one generation, which is now a legacy-row concern rather than a description of kernel behavior.
