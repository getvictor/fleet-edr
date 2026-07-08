# Bound detection retry log volume

## Why

The detection processor logs `detection failure, will retry batch` at warn, once per batch retry, whenever an event's subject or flow process cannot be materialized yet. That miss is an expected, transient ordering race (a concurrently processed batch has not committed the process row): the processor nacks the batch and re-evaluates it on the next poll tick, and rule evaluation raises the retryable `ErrProcessNotYetMaterialized` inside a grace window. The retry itself is correct, but the warn line is not bounded: under any sustained materialization-miss condition the same batch re-nacks on every tick, so the line repeats for the whole grace window per stuck batch. We observed ~130 warn/min from a single host during one such condition (issue #631). These logs also flow over OTLP to the collector (SigNoz), so at fleet scale this is an ingestion-cost and signal-to-noise problem, not just local disk.

The condition is not upgrade-specific: a replica behind on graph materialization, an agent that stopped sending fork/exec while its processes keep connecting, a ClickHouse restore or replica re-seed, or a batch of orphaned flows for a long-lived process all leave flows without a materialized subject process for a sustained period.

## What changes

- **The processor distinguishes a materialization miss from a genuine failure.** When rule evaluation returns the retryable `ErrProcessNotYetMaterialized` error class, the processor logs the retry at debug (not warn) and increments a new counter. A genuine (non-materialization) detection failure, such as an alert persistence error, keeps its per-retry warn line because it is rare and each occurrence is a real fault an operator must see. The graph-builder failure path is unchanged.
- **A new stable counter `edr.detection.materialization_retries`** is the observable signal for the retry rate. Operators alert on a sustained non-zero rate instead of scraping the retry log. The counter is attribute-free to bound cardinality (a per-host or per-rule label would reproduce the fan-out the log flood already caused). The default `info` log level drops the debug retry line from both stderr and the OTLP export, so normal operation carries the counter alone; raising the log level to debug brings the per-retry line back for troubleshooting.
- **The processor now takes a metrics recorder.** `Runner.SetMetrics` propagates the recorder to the processor (previously only the periodic sweeps and the engine received it).

### Not in this change

- Rate-limited or aggregated summary logging. A debug line plus a counter meets the acceptance (bounded volume, still observable) without a per-replica suppression map, which the stateless-server constraint (ADR-0010) would otherwise require a justification for.
- Any change to the grace windows, the nack/re-claim retry mechanism, or the graph-builder failure log.

## Acceptance

- A sustained materialization-miss condition produces bounded log volume: no warn line per batch retry, and no debug line at the default log level.
- The signal is still observable: `edr.detection.materialization_retries` counts every materialization-miss retry so a genuinely stuck backlog is detectable.
- A genuine detection failure still logs at warn.
