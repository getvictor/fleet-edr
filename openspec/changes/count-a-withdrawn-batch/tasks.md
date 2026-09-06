# Tasks

## 1. Carry the tally to the transition that ends the batch

- [x] 1.1 Return the tally alongside the error on both of the engine's error paths, so the caller can decide rather than the engine.
- [x] 1.2 Record it in the processor when the queue reports the whole batch withdrawn, and only then.
- [x] 1.3 Compare against the batch size rather than against zero, since a partial withdrawal leaves rows that are evaluated again.
- [x] 1.4 Note the archive-order dependency in the proposal: this delta modifies a requirement that only an in-flight change has added, so that change has to archive first, and the names sort the wrong way.
- [x] 1.5 Update the recorder's contract, which described the acknowledgement as the only transition, and drop the stale claim-lease inaccuracy that #817 removed.
- [x] 1.6 Sweep every other place that framed the record as happening only after an acknowledgement. Nineteen sites in the end, across two passes: the port, the counter's description and residual list, the recorder, the eval-stats contrast in five files, the processor's field comment, the runner's setter, both bootstraps, the deadlock-retry rationale, and the engine's tally comments. The first pass grepped case-sensitively for the phrasings it had already seen and missed six; the second grepped `acknowledg` case-insensitively across every comment, which is the sweep that should have been run first.
- [x] 1.7 Restate `Stable counter names` with the terminal-transition rule, in this change and identically in the four other active deltas that carry it. Without that the archived specs would both require and forbid recording on withdrawal, and spectrace requires concurrent restatements to be identical.
- [x] 1.9 State the RIGHT exactly-once mechanism. It is set-aside being terminal, not the withdrawing statement being restricted to rows the same transaction reset: that statement's predicate is the requested ids in the pending state, so it can also match a row another nack returned to pending. The count is the same and the invariant is not, which matters to anyone changing the queue.
- [x] 1.8 Correct the queue's own description of #840, which said the replacement's Ack still lands. Since #817 made Ack claim-conditional, a stale nack clears the stamp and the replacement's Ack is rejected; and a spurious set-aside needs no repetition, because the attempt bound is carried on the row.

## 2. Tests

- [x] 2.1 A fully withdrawn batch records what it matched, in both the durable record and the counter.
- [x] 2.2 A partly withdrawn batch records nothing.
- [x] 2.3 An ordinary nack still records nothing, so the fix is not "record on every failure".
- [x] 2.4 Pin the RESIDUAL: a batch that evaluated on one attempt and is withdrawn by a fold failure on a later one records nothing. Review was right that the first version of the requirement claimed more than the code does.
- [x] 2.5 Finish the partial-withdrawal scenario. Its first version stopped at the nack, which passes just as well against a processor that had stopped counting the survivor at all; the survivor's own attempt is now driven and asserted.
- [x] 2.6 Document the THIRD residual, which the partial case creates: whatever the withdrawn events alone matched is dropped, because the figure is aggregated per rule and host and cannot say which event a match came from. Stated in the requirement, the metric description, and the port.
- [x] 2.7 Cover the ENGINE's two returns directly. The processor's tests stub the evaluator, so they prove nothing about whether a tally is handed over; the two mutants that drop it survived until this was added.
- [x] 2.8 Mutation-test: discarding the tally on a withdrawal, loosening the condition to any withdrawal, and dropping the tally from either engine return.
