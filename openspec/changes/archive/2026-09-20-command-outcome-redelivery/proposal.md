# A command whose outcome was lost is offered again

Issue #1062. An outcome the agent writes to a control stream that is already dead is lost for good, and the command stays `acked` forever.

The agent's `Send` into a half-open TCP connection returns no error, so the control client learns nothing until its keepalive fails. Measured on edr-dev while building #948: restarting the network extension cut the agent's control stream, and the keepalive noticed 13 to 21 seconds later. Command 850, a containment release, was applied by the agent within about 70 ms and logged as completed there, and it is still `acked` on the server. Anything that cuts a connection has the same effect: an extension update, a network change, sleep.

Redelivery is the recovery the system already has: the agent's ledger records every command's terminal outcome and replays it rather than repeating the side effect. But the gateway and the poll path both list only `pending` commands, so a command that reached `acked` is never offered again, and nothing ever asks for its outcome.

## What changes

- **A command acked without an outcome is offered again.** While a host holds a control connection, the gateway offers it, alongside the host's pending backlog, every command of that host which has been `acked` for longer than a grace period and has no outcome. The agent's executor replays the recorded outcome, which moves the command to its terminal status.
- **The grace period is longer than any legitimate execution.** A command is offered again only 60 seconds after it was acked, so a command still running (`set_network_containment` waits up to 15 seconds for the extension to confirm) is never duplicated by the server's impatience.
- **Redelivery stops at 7 days.** Beyond that the agent may have pruned its ledger, which keeps outcomes for 30 days, and an agent that has forgotten a command would run its side effect again rather than replay it. A command still acked after 7 days keeps that status: it was delivered, and its outcome is not known.
- **No duplicate pushes while one is in flight.** The connection's in-flight set already suppresses a second offer of the same command until its outcome arrives, which is what keeps a one-second watch tick from pushing the same command repeatedly.

## Out of scope

- **The poll path.** A host without a control connection polls for `pending` commands, and an acked one cannot be returned to that query without saying it is pending, which would claim the side effect had not run. Recovering an outcome lost on the poll path is #1080.
