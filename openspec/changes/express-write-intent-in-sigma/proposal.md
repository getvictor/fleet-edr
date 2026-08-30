# An open event says who wrote and what the write meant

## Why

`sudoers_tamper` is the last Go rule #761 needs converted, and it is the one that does not fit the shape the earlier conversions used. Its decision reads two separate facts about the same `flags` value, and the second one applies only to one writer: sudo opens `/etc/sudoers` write-mode to take a `LOCK_EX` flock, a write by access mode with no intent to change the contents, and suppressing that is not the same test as "is this a write".

#772 assumed the two masks compose into one write-intent boolean. They do not. Read together they are `write-access AND (writer is not sudo OR intends to mutate)`, and collapsing them either loses the flock suppression or applies it to every writer, which would let anything opening a sudoers file with bare `O_WRONLY` through.

## What changes

An open event supplies three fields it did not before: the writing process's image, whether the open carried write access, and whether it carried a flag that changes the file's contents. The rule then expresses the suppression the way Sigma expresses a conditional exception, as a named filter the condition subtracts, rather than as a branch in Go.

`sudoers_tamper` is converted onto that. Its Go matcher and its two mask parameters are removed; the masks become the two boolean fields, derived from the flags when the event is decoded. The writer's image is the part resolved lazily, because it needs the process graph and a rule reaches it only after the far cheaper path test has narrowed the events.

## What we found while converting it

Both mask tests are **inert against any agent shipping today**, and the conversion deliberately keeps them anyway.

Since #301 (2026-05-31) dropped the broad `NOTIFY_OPEN` subscription, the only source of `open` events is `FileTamperSubscriber`, which re-emits `NOTIFY_CREATE` and `NOTIFY_WRITE` on sudoers paths with a **constant synthetic flag set**, `O_WRONLY|O_CREAT|O_TRUNC` (1537). Against a constant, write access is always set and the mutating bits are always set, so the flock suppression cannot fire and no read-only open ever arrives to be filtered. The rule fires on path alone in practice.

Keeping the tests is not speculative: an agent predating #301 sends real `open(2)` flags, and dropping them would make a read-only open of `/etc/sudoers` on such a host start alerting. A test records this so the fields can be retired deliberately once those agents are gone, rather than a later reader finding two masks that look pointless and guessing. Filed as #801.

## The `mapped` trade

The converted rule is `portable: mapped`, not `standard`. Sigma's file taxonomy has no field for "this open intended to change the contents", because Sigma models a file event as a completed creation or modification rather than as an `open(2)` with flags. We could have dropped to `standard` by discarding the flock suppression, and chose the detection over the portability score: the suppression is the difference between the rule and a rule that alerts every time anyone runs `sudo`.

`Image` on an open event is Sigma taxonomy, so only the two booleans cost us the `standard` classification.

## The gate

`sudoers_tamper`'s test and fixture files are **unchanged, not one line**, which is #761's acceptance criterion stated literally. Its 14 cases pass against the detection block as written. The equivalence property compares the shipped detection against a frozen oracle across paths, flag combinations and writers, and every mutation of the rule fails it.

One mutation survives that property and is worth stating plainly: removing `WriteIntent` from the rule changes no verdict, because our adapter already withholds `TargetFilename` from a read-only open. It is retained because `mapped` promises another engine can run this rule, and an engine supplying `TargetFilename` on every open needs the rule to say for itself that it only wants writes. A separate test evaluates the shipped detection under a literal field supplier to pin exactly that.

## Impact

No change to what fires. The rule detects what it detected, on the same events, and the tests that were already pinning it are the evidence.
