# Say so when the timeline cannot scope to the alert chain

## Why

The graph and the timeline are meant to share one alert focus. The timeline's scope is keyed on the `(pid, pidversion)` pair, so it can only honour that focus when the chain's processes carry a pidversion. When none of them do, the chain resolves to an empty generation list and the timeline falls back to the full host event stream.

Falling back is right. Doing it silently is not. The operator sees four processes in the graph and a thousand rows in the timeline beside it, with nothing to say the two views are answering different questions, and reads that as a product defect. It was reported exactly that way during v0.5.0-rc.2 demo QA, where every process in the demo corpus has a NULL pidversion so every alert's timeline is unscoped.

Real agent data is not immune: on a live macOS host 534 of 14,099 process rows carried no pidversion, so a chain that happens to include one of them is scoped on the rest and silently loses that process's events.

## What changes

The timeline already labels itself "Scoped to the alert chain" when the scope is applied. It now also says something when the scope was requested and could not be applied, naming the reason. No change to which events are listed: the fallback behaviour is unchanged, only its visibility.

## Impact

- `ui/src/components/HostTimeline.tsx`, `ui/src/components/ProcessTree.tsx`, `ui/src/components/HostTimeline.scss`
- No server, API, or persistence change.
