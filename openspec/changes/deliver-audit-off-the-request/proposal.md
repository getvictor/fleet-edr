# Deliver a change's audit row off the request that made it

Issue #1089. A change committed its audit entry with itself and then delivered the entry on its own goroutine, reading up to a full batch of pending entries and recording them one at a time before the handler could answer. In the steady state that is the single entry the change just wrote. After an audit-store outage it is not: the first requests back meet the backlog, and a slow store then delays a response whose change has already taken effect. An operator who gives up on a destructive action and retries has issued it twice.

## What changes

- **A change asks for delivery instead of performing it.** The request commits its entry, signals the context's sweep, and answers. Requests arriving while a pass is running are answered by that one pass rather than one pass each, and a pass that fills its batch asks for the next itself, so a burst is drained over as many passes as it takes rather than leaving the remainder for the interval.
- **The periodic sweep stays, and is what makes delivery depend on the entry rather than on the signal.** A signal is in-process: it is lost by a replica that exits between the commit and the sweep, and it never reaches the replica that has to deliver an entry another one wrote.
- **The sweeps outlive the shutdown signal.** They run until the server has finished draining, so a change made during the drain window still has something to ask.

## Out of scope

The at-least-once guarantee, the entry encoding, and which changes commit an entry are unchanged.
