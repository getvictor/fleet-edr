# Tasks

- [x] Give the agent's ledger interface the read-only lookup its store already implements.
- [x] Add an executor entry point that replays a recorded outcome and leaves an unrecognised command alone.
- [x] Have the poll ask for this host's acknowledged commands on its own interval and replay each.
- [x] Cover the replay, the unrecognised command, the failed lookup, a command executing in this process, and the cadence.
