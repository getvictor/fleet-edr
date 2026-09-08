# Tasks

- [x] Hold the host claim lock across the acknowledgement, blocking rather than try-lock, since an acknowledgement has nothing else to do.
- [x] Hold it across the detection-stage requeue too, which is the same statement shape by the other exit.
- [x] State in `Ack`'s documentation that it does not serialize itself against a claimer and that the caller must.
- [x] Make the test coordinators run their `WithLock` callback, since a stub that swallowed it would pass against a processor that never acknowledged.
- [x] Pin both windows with tests that observe what the event log had been told when the locked callback returned.
