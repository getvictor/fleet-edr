# Tasks

## 1. Make returning a batch conditional on the claim

- [x] 1.1 Take the claim stamp, matching what acknowledging has taken since #817.
- [x] 1.2 Establish ownership by reading the held events under lock, since neither write can express the check and report what it checked.
- [x] 1.3 Key both writes on the owned set rather than on the events that were asked for.
- [x] 1.4 Tell the caller whether it still held the claim, as acknowledging does, and report a lost one. Reporting only "nothing withdrawn" is the same answer a held batch gets when no event reached its bounds, which would have made this the one silent way to lose a claim.
- [x] 1.5 Correct the comments that recorded this as an open limitation, in the queue and in the two changes that documented it as a bound on what they promise.

## 2. Tests

- [x] 2.1 A stale attempt's return leaves the replacement's claim intact, counts no attempt, and leaves the replacement able to acknowledge. The last of those matters: without it the test passes against an implementation that refuses everything.
- [x] 2.2 A return naming held AND unheld events confines every effect to the held ones, with an unheld event parked at its bounds so the withdrawal statement is exercised and not just the reset.
- [x] 2.3 Mutation-test all three: dropping the ownership check, and keying either write on the requested events. The last two survived until 2.2 existed, because every other test hands over exactly what it holds.
