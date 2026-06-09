# Design: `dns_c2_beacon` correlation rule

## Context

The detection engine evaluates each rule against the current batch of raw events with a `GraphReader` for retrospective
graph queries:

```go
// server/rules/api/types.go
type Rule interface {
    ID() string
    Techniques() []string
    Doc() Documentation
    Evaluate(ctx context.Context, events []Event, gr GraphReader) ([]Finding, error)
}
```

`GraphReader` today exposes `GetProcessByPID`, `GetChildProcesses`, `GetExecChain` (`server/detection/api/service.go`).
The concrete `*mysql.Store` also has `GetNetworkEventsForProcess(hostID, pid, TimeRange) ([]Event, error)` returning a
pid's `network_connect` and `dns_query` events (`server/detection/internal/mysql/processes.go:389`), but it is not on
the interface, so no rule can reach DNS/network events. Exposing it is the one structural change required.

`osascript_network_exec` is the template for cross-stream correlation: it triggers reverse-direction on the event that
lands last (the temp exec), then walks the graph to reassemble the chain. Reverse-direction is race-immune: by the time
the trigger event lands in batch N+1, the earlier links are already materialized from batch N.

## The correlation

`dns_c2_beacon` proves the canonical C2 shape across all three streams:

1. A process is `exec`'d (identity plus suspicion context).
2. It resolves a domain: a `dns_query` with `response_addresses`.
3. It connects to a resolved address: a `network_connect` whose `remote_address` is in that query's
   `response_addresses`.

**Trigger:** on each `network_connect` event in the batch (the last link). For the connecting pid, call
`GetNetworkEventsForProcess(pid, window)` and find a `dns_query` whose `response_addresses` contains this connection's
`remote_address`. That single join proves "this process resolved this domain, then connected to the address it resolved
to". `GetProcessByPID` supplies the `exec`/process row for identity and the suspicion gate.

**Address matching:** compare parsed IP values, not raw strings. The rule normalizes both the connection's
`remote_address` and each `response_addresses` entry via `net.ParseIP` before comparing, so equivalent IPv6 forms (zero
compression, case) do not cause false negatives.

**Selection when several queries match:** if more than one `dns_query` for the process resolves to the connection's
`remote_address` within the window (for example two domains that both resolve to the same CDN IP), the rule cites the
most recent matching query (highest `timestamp_ns`); ties break on the lexicographically smallest query name. This keeps
finding attribution deterministic, which matters for the fixture tests and the demo.

**Window:** the `dns_query` and `network_connect` must fall within a bounded window for the same pid (start with 30s,
matching the existing `osascript` window; the resolve-to-connect latency is sub-second in practice, so this is
generous).

## The suspicion gate (locked: option C, both signals)

A naive "resolved-then-connected" join fires on every browser fetch. The gate keeps false positives near zero. The
chosen design uses both signals:

- **Process context** (hard gate): fire only when the process is suspicious by exec context: exec'd from a temp or
  world-writable path, or a script interpreter (osascript/python/bash/sh) whose parent is non-interactive. Re-uses
  signals the catalog already encodes.
- **Domain anomaly** (severity booster): when the resolved `query_name` is anomalous (high Shannon entropy or a long
  random label, the DGA shape), raise severity from `High` to `Critical` and add the `T1568.002` technique. It is not a
  hard gate, so a "normal-looking" C2 domain from a suspicious process still fires at `High`.

Rationale: process context alone is precise but misses C2 from a normal-looking domain; domain anomaly alone risks false
positives on legitimate long subdomains. Process-context-AND-join is precise, and domain anomaly as a booster keeps the
DGA signal without making it a hard gate. Benign browser traffic never fires (the browser is not a suspicious-context
process). The exact entropy threshold is tuned empirically during implementation against the efficacy corpus and the
captured benign demo traffic; the design fixes the shape (entropy/length), not a magic number.

For the efficacy corpus, the positive scenario uses a temp-path-exec'd binary that resolves a high-entropy domain and
connects to the resolved IP (trips process context, the join, and the anomaly booster). Negatives: a browser resolving
plus connecting to a normal domain (no process context); a suspicious process that resolves but connects to an address
it never resolved (no join).

## Finding shape

```
Finding{
  RuleID:     "dns_c2_beacon",
  Severity:   High,            // Critical when the domain anomaly signal also trips
  Title:      "C2 beacon: suspicious process resolved and connected to <domain>",
  ProcessID:  <connecting process row id>,
  EventIDs:   [<exec event>, <dns_query event>, <network_connect event>],
  Techniques: ["T1071.004"]    // plus "T1568.002" when the entropy signal contributes
}
```

Dedup is by `ProcessID` via the engine's existing subject dedup, so a beaconing process that connects repeatedly
produces one alert, not one per connection.

## Why reverse-direction (trigger on network_connect)

The chain completes at the connection. Triggering on the `dns_query` (forward) would require waiting to see whether a
connection follows, across batch boundaries; triggering on the `network_connect` means the `dns_query` is already
ingested and the join is a single retrospective lookup: race-immune, no state held in the engine (consistent with the
stateless-server constraint).

## Scope boundaries

- Classic UDP/TCP/53 DNS only; encrypted DNS (DoH/DoT) bypasses the proxy and is out of scope (roadmap).
- The suspicion gate is heuristic, not threat-intel; the bar is "demonstrably correlates across three streams", not
  production reputation. The DGA check is entropy/length, not a trained model.
- No engine statefulness: the rule holds nothing between batches; all correlation is retrospective graph reads.
- `GetNetworkEventsForProcess` is added to the interface unchanged in behavior; the rules test kit gains a fake
  implementation backed by the in-memory scenario store.

## Activate-flow implementation note

`activate` must enable the content filter and then the DNS proxy. The current `enableContentFilter()` and
`enableDNSProxy()` in `extension/edr/edr/main.swift` each call `exit(EXIT_SUCCESS)` / `exit(EXIT_FAILURE)` inside their
own completion handlers, so they cannot simply be called in sequence (the first would exit the process). The
implementation refactors them to chain via a completion callback (enable the filter, then on success enable the DNS
proxy, then exit) rather than exiting from each handler.
