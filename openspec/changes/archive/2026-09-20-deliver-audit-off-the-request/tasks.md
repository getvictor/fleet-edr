# Tasks

- [x] Turn the post-commit call into a request for a pass rather than a pass, coalescing on a single-slot signal.
- [x] Have the sweep select on both the signal and its interval, and ask itself for another pass when it fills a batch.
- [x] Give each context's services the drain their context sweeps, rather than one built per service.
- [x] Keep the background loops alive through the shutdown drain window.
- [x] Cover the new behaviour: no wait on the audit store, coalescing, a burst larger than one pass, the interval with no signal, and what the sweep reports.
