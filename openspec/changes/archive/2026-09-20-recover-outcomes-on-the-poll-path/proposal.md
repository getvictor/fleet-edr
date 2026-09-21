# Recover a lost command outcome on the poll path

Issue #1080. An outcome the agent fails to report is dropped and nothing asks for it again. The execution succeeded and the ledger recorded it, but the report did not reach the server, so the command stays `acked` there with its outcome only on the host: the operator sees a response action that was delivered and never finished, for as long as the row lives.

Issue #1062 closed this for a host holding a control connection, where the gateway re-offers an acknowledged command after a grace period and the agent replays its recorded outcome. A host on the poll fallback has nothing that would ask. It polls for `pending` commands, and an acknowledged one is not in that answer.

## What changes

- **The poll asks about the outcomes the server is still waiting for.** Alongside its poll for pending work, the agent asks for its own acknowledged commands and re-reports what its ledger holds for each. The endpoint already takes a status and pins the host to the token, so nothing changes on the server.
- **A command the ledger does not know is left alone.** The ledger may have been pruned or replaced, and this path cannot tell that from a command that never ran. Reporting an outcome would invent one the host never produced, and running the command would repeat a side effect the operator asked for once, so the command keeps the status it has.
- **The question runs on its own slower cadence.** The poll is every few seconds and this answer is empty in every ordinary case, so asking each time would double a host's request rate for a path that almost never has work.

## Out of scope

The control-channel re-offer (#1062) is unchanged, and no new endpoint or command status is introduced.
