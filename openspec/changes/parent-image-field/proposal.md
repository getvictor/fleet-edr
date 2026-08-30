# A rule can match on the parent process

## Why

`ParentImage` is standard Sigma taxonomy and **11 of the 69 macOS corpus rules read it**, so without it those rules cannot load. Our exec payload carries `ppid`, not the parent's path.

## The issue's open decision, settled against its own proposal

#771 says to "denormalise the parent path onto the exec event at ingest" and leaves the storage cost open. The pipeline settles it, and not in favour of that approach. `Processor.evaluateAndAck` runs "detection rules **after** processes are materialized", while events are claimed from a log that already stored them. Enriching at ingest would therefore run before the parent is materialized, and the common case is the worst one: a process forked moments earlier arrives in the same batch, so its row does not exist yet. An empty `ParentImage` would be written permanently, on exactly the events most likely to matter, with no way to correct it short of a backfill.

Resolving at evaluation is both cheaper and more correct. The lookup already exists and is already proven: `shell_from_office` called `GetProcessByPID(ctx, hostID, ppid, evt.TimestampNs)` and read `.Path`. That IS `ParentImage`. So this needs no new lookup, no schema change, no migration, no storage and no backfill.

For the record, since the issue asked: had we stored it, the cost would have been **+31 bytes on a 411-byte exec payload, about 7.5%**, across 673,523 exec events, of which 99.996% carry a resolvable ppid.

## What changes

`sigmabind` stays graph-free, which is deliberate: it defines matching over an interface precisely so its semantics stay testable against literal values. The caller resolves the parent and supplies it, and the taxonomy exposes it as `ParentImage`. That keeps the lookup where the retry semantics live, and composes with #794: when the engine builds the adapter once per event, it resolves the parent once per event rather than once per rule.

`shell_from_office` converts onto it, which proves the field end to end and closes one of the two rules #761 is still blocked on.

## Measured result

Against the SigmaHQ corpus, macOS rules passing the load-time field check go from **57 of 69 to 68 of 69**. The one remaining is blocked on `OriginalFileName`, a Windows PE version-resource field with no macOS equivalent.

`shell_from_office` becomes the first rule to reach **`portable: standard`**: it reads only Sigma's own taxonomy, so any Sigma-compatible engine can evaluate it. That is what the issue predicted this enrichment would buy, and the classification derives it rather than being told.

## A new drift surface, guarded

Sigma cannot reference a list defined elsewhere, so converting a rule that read the shared `unix_shells` list necessarily inlined it. `suspicious_exec` still reads the shared list, so the two descriptions of one set can now part company. `TestSharedShellListMatchesTheShippedDetection` asserts they agree in both directions, and is mutation-verified: adding a shell to `lists.yml` without the detection fails it.

This is worth watching as more rules convert. It is a real cost of the format, not of this change.

## Impact

No behaviour change. The rule's seven table cases pass unchanged, including the negatives that pin exact-path matching, and its pre-conversion predicate is frozen in the equivalence property as the oracle.
