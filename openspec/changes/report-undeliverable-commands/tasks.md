# Tasks

- [x] Add a per-host read of commands that aged out undelivered, windowed, counting only `expired`.
- [x] Remove `CountPending`, which had no production caller and could not answer the per-host question.
- [x] Derive a degraded condition from that count, carrying the most recent expiry as its transition instant.
- [x] Fold it into the host list, the host detail, and the health rollup, so the header cannot read healthy while the condition stands.
- [x] Ask about every host rather than only telemetry candidates: a host claiming no capturing provider can still be failing to take commands.
- [x] Declare both ports where they are consumed and adapt them in `cmd/main`, so neither context imports the other.
- [x] Treat a read failure as a missing condition, not a failed host page.
