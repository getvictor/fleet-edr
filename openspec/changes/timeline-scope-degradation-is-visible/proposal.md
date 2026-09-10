# Say so when the timeline cannot scope to the alert chain

## Why

The graph and the timeline are meant to share one alert focus. The timeline's scope is keyed on the `(pid, pidversion)` pair, so it can only honour that focus when the chain's processes carry a pidversion. When none of them do, the chain resolves to an empty generation list and the timeline falls back to the full host event stream.

Falling back is right. Doing it silently is not. The operator sees four processes in the graph and a thousand rows in the timeline beside it, with nothing to say the two views are answering different questions, and reads that as a product defect. It was reported exactly that way during v0.5.0-rc.2 demo QA, where every process in the demo corpus has a NULL pidversion so every alert's timeline is unscoped.

Real agent data is not immune: on a live macOS host 534 of 14,099 process rows carried no pidversion, so a chain that happens to include one of them is scoped on the rest and silently loses that process's events.

## What changes

No change to which events are listed. The fallback behaviour is unchanged; only its visibility is. The timeline already labelled itself "Scoped to the alert chain" when the scope applied, and it now distinguishes every outcome that label used to cover:

- **Scoped in full**: unchanged, the existing label.
- **Scoped in part**: the scope applied, but some of the chain's processes carry no generation and their events are absent. This is the worst case to leave silent, because a scoped list gives no reason to suspect anything is missing. It now states that only part of the chain was reached, without claiming how many processes were omitted: the count would come from tree nodes, and the tree aggregates identical leaf descendants into synthetic group nodes, so it would report groups as processes.
- **Not scoped, no generations**: nothing in the chain carries one. Full host stream, said so.
- **Not scoped, chain empty**: `findAlertChain` resolved nothing because the alerted process is not in the fetched tree. Also the full host stream, but a different cause with a different fix, so it gets its own wording rather than being told it has a generation problem.

The last two were found by review after the first draft handled only the all-missing case.

## Impact

- `ui/src/components/HostTimeline.tsx`, `ui/src/components/ProcessTree.tsx`, `ui/src/components/HostTimeline.scss`
- No server, API, or persistence change.
