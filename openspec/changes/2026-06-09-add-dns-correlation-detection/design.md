# Design: `dns_c2_beacon` correlation rule

## Context

The detection engine evaluates each rule against the current batch of raw events with a `GraphReader` for retrospective graph queries:

```go
// server/rules/api/types.go
type Rule interface {
    ID() string
    Techniques() []string
    Doc() Documentation
    Evaluate(ctx context.Context, events []Event, gr GraphReader) ([]Finding, error)
}
```

`GraphReader` today exposes `GetProcessByPID`, `GetChildProcesses`, `GetExecChain` (`server/detection/api/service.go`). The concrete `*mysql.Store` also has `GetNetworkEventsForProcess(hostID, pid, TimeRange) ([]Event, error)` returning a pid's `network_connect` and `dns_query` events (`server/detection/internal/mysql/processes.go:389`), but it is not on the interface, so no rule can reach DNS/network events. Exposing it is the one structural change required.

`osascript_network_exec` is the template for cross-stream correlation: it triggers reverse-direction on the event that lands last (the temp exec), then walks the graph to reassemble the chain. Reverse-direction is race-immune: by the time the trigger event lands in batch N+1, the earlier links are already materialized from batch N.

## The correlation

`dns_c2_beacon` proves the canonical C2 shape across all three streams:

1. A process is `exec`'d (identity + suspicion context).
2. It resolves a domain — a `dns_query` with `response_addresses`.
3. It connects to a resolved address — a `network_connect` whose `remote_address` ∈ that query's `response_addresses`.

**Trigger:** on each `network_connect` event in the batch (the last link). For the connecting pid, call `GetNetworkEventsForProcess(pid, window)` and find a `dns_query` whose `response_addresses` contains this connection's `remote_address`. That single join proves "this process resolved this domain, then connected to the address it resolved to" — the exec, DNS, and network events are now all in hand. `GetProcessByPID` supplies the `exec`/process row for identity and the suspicion gate.

**Window:** the `dns_query` and `network_connect` must fall within a bounded window for the same pid (start with 30s, matching the existing `osascript` window; the resolve→connect latency is sub-second in practice, so this is generous).

## The suspicion gate (the open design decision)

A naive "resolved-then-connected" join fires on every browser fetch. The gate keeps false positives near zero. Three options:

- **A — process context**: fire only when the process is suspicious by exec context: exec'd from a temp / world-writable path, or a script interpreter (osascript/python/bash/sh) whose parent is non-interactive. Re-uses signals the catalog already encodes.
- **B — domain heuristic**: fire only when the resolved `query_name` is suspicious: a small committed watchlist, or a DGA-style signal (high Shannon entropy / long random label). Catches algorithmically-generated C2 domains.
- **C — both (recommended)**: fire on (suspicious process context **A**) **AND** (resolved-then-connected). The domain heuristic **B** raises severity (`High` → `Critical`) and contributes the `T1568.002` technique when it triggers. Rationale: A alone is precise but misses C2 from a "normal-looking" process; B alone risks FPs on legitimate long subdomains; A∧(join) is precise, and B as a severity booster keeps the DGA signal without making it a hard gate. Benign browser traffic never fires (the browser is not a suspicious-context process).

For the efficacy corpus, the positive scenario uses a temp-path-exec'd binary that resolves a high-entropy domain and connects to the resolved IP (trips A, the join, and B). Negatives: a browser resolving + connecting to a normal domain (no A); a suspicious process that resolves but does not connect to the resolved address (no join).

## Finding shape

```
Finding{
  RuleID:     "dns_c2_beacon",
  Severity:   High,            // Critical when the domain heuristic also trips
  Title:      "C2 beacon: suspicious process resolved and connected to <domain>",
  ProcessID:  <connecting process row id>,
  EventIDs:   [<exec event>, <dns_query event>, <network_connect event>],
  Techniques: ["T1071.004"]    // + "T1568.002" when the entropy signal contributes
}
```

Dedup is by `ProcessID` via the engine's existing subject dedup, so a beaconing process that connects repeatedly produces one alert, not one per connection.

## Why reverse-direction (trigger on network_connect)

The chain completes at the connection. Triggering on the `dns_query` (forward) would require waiting to see whether a connection follows, across batch boundaries; triggering on the `network_connect` means the `dns_query` is already ingested and the join is a single retrospective lookup — race-immune, no state held in the engine (consistent with the stateless-server constraint).

## Scope boundaries

- Classic UDP/TCP/53 DNS only; encrypted DNS (DoH/DoT) bypasses the proxy and is out of scope (roadmap).
- The suspicion gate is heuristic, not threat-intel; the bar is "demonstrably correlates across three streams," not production reputation. The DGA check is entropy/length, not a trained model.
- No engine statefulness: the rule holds nothing between batches; all correlation is retrospective graph reads.
- `GetNetworkEventsForProcess` is added to the interface unchanged in behavior; the rules test kit gains a fake implementation backed by the in-memory scenario store.
