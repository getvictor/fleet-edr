# Tasks

## 1. Carry the tally to the transition that ends the batch

- [x] 1.1 Return the tally alongside the error on both of the engine's error paths, so the caller can decide rather than the engine.
- [x] 1.2 Record it in the processor when the queue reports the whole batch withdrawn, and only then.
- [x] 1.3 Compare against the batch size rather than against zero, since a partial withdrawal leaves rows that are evaluated again.
- [x] 1.4 Update the recorder's contract, which described the acknowledgement as the only transition, and drop the stale claim-lease inaccuracy that #817 removed.

## 2. Tests

- [x] 2.1 A fully withdrawn batch records what it matched, in both the durable record and the counter.
- [x] 2.2 A partly withdrawn batch records nothing.
- [x] 2.3 An ordinary nack still records nothing, so the fix is not "record on every failure".
- [x] 2.4 Cover the ENGINE's two returns directly. The processor's tests stub the evaluator, so they prove nothing about whether a tally is handed over; the two mutants that drop it survived until this was added.
- [x] 2.5 Mutation-test: discarding the tally on a withdrawal, loosening the condition to any withdrawal, and dropping the tally from either engine return.
