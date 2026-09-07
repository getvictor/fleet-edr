# Tasks

## 1. Durable completion state

- [x] 1.1 Add a table recording which one-shot backfills have completed, keyed by name rather than a boolean per backfill.
- [x] 1.2 Read completion by primary key, so the boot after a successful pass costs a lookup rather than a scan.
- [x] 1.3 Record completion only after the pass returns successfully.

## 2. Wire it into the pass

- [x] 2.1 Check before taking the leader lock, which is what removes the scan from a later boot.
- [x] 2.2 Check again inside the lock, which is what holds when two replicas start together rather than in sequence.
- [x] 2.3 Leave the exclusions and the idempotence #870 pinned untouched.

## 3. Tests

- [x] 3.1 A start after a completed pass skips it, proven with a probe row a pass that ran would have credited.
- [x] 3.2 A pass that fails records nothing, and the next start runs and credits the rows it did not reach.
- [x] 3.3 A pass that credited SOME rows and then stopped records nothing, made deterministic by placing the failure in the second batch by id rather than by cancelling a context mid-walk, which would race the batch loop and complete the pass whenever it lost.
- [x] 3.7 A start cut short before the pass begins records nothing either, which is the cheap end of the same ordering.
- [x] 3.4 A replica taking the lock after a peer finished looks again and skips, which the check outside the lock cannot cover.
- [x] 3.5 Recording completion twice is harmless, and completion is per backfill rather than one flag for all of them.
- [x] 3.6 Take the sole leadership as given in all of the above: GET_LOCK names are global to the MySQL server, so tests sharing the real lock name contend with each other and with anything else on that instance.
