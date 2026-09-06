# Tasks

- [x] The gate reads the best p99 across trials rather than one. Contention is intermittent, so one trial runs clean; a real regression is in every trial. The minimum measures capability, a single reading measures capability plus contention.
- [x] It stops as soon as a trial meets the budget, so the healthy case costs what it did before and the extra trials are paid for only when the first reading looks bad.
- [x] The budget was NOT widened, because measuring showed it is not too tight: 173 to 210 microseconds idle and 488 to 743 under 16-way load, all inside 1 ms. Widening would have loosened a gate that was already correct about the code.
- [x] Verified it survives what used to break it: five consecutive runs under 32-way CPU load, twice the core count.
- [x] Verified it still fails on a real regression, injected as a delay on every call, and that the failure output shows the whole distribution shifted rather than only the tail. That difference is what tells a reviewer which of the two they are looking at.
- [x] The failure message names the reading method and prints the best trial's distribution, so the verdict and the evidence come from the same trial.
- [x] The scenario wording says how p99 is read. "The recorded p99" was ambiguous between one sample and a stable reading, and that ambiguity is what let a machine-dependent measurement look conformant.
