# Say when the timeline could not narrow because the tree read failed

## Why

Opening an alert on a busy host, the page tells the analyst two contradictory things at once. The graph reports `Error: API error: 502`. Switch to the timeline and it lists the host's entire event stream with no indication that anything went wrong, which reads exactly like a successful unscoped view.

Reported from the dogfood deployment on `v0.5.0-rc.4`. The read fails there for a separate reason, an unbounded count that outruns the server's write timeout, fixed in its own change. This one is about what the page says when that read fails for any reason.

The cause is in the chain-coverage logic added by #968. A failed read and a read still in flight are treated alike, and neither produces a notice:

```ts
const treeLoaded = !loading && error === null;
return treeLoaded ? { unavailable: "chain-unresolved", partial: false } : { partial: false };
```

Silence is right for a read in flight, where a message would appear and then vanish as the tree resolves. It is wrong for a read that failed, which is a settled outcome the operator can act on. The existing wording could not be reused, because "this alert's process is not in the loaded process tree" is a claim about a tree that never loaded.

## What changes

- A third `ChainScopeGap`, for a tree read that failed, with its own sentence: the timeline says the process tree could not be loaded and that it is therefore showing the whole host.
- The in-flight case keeps its silence.

## What does not change

Which events the timeline lists. The unscoped stream is real data the server returned, and it stays visible: the defect is that it was unlabelled, not that it was there.

## Impact

- Affected specs: `web-ui`
- Affected code: `ui/src/components/HostTimeline.tsx`, `ui/src/components/ProcessTree.tsx`
