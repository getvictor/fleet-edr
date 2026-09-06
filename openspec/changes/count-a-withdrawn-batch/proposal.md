# A monitor match survives its batch being withdrawn

## Why

A monitor-mode match resolved before a batch failed was recorded nowhere if that batch was ultimately set aside.

The tally is discarded on every retryable error, which is right and stays right: the batch comes back and produces the same matches again, so recording per attempt counts a retried batch once per retry. The gap is the terminal case. Once a batch passes its retry bounds it is withdrawn from processing for good, and there is no later attempt to be counted on, so the matches it resolved are lost.

The count is what the detection-tuning table shows an operator deciding whether to promote a monitor-mode rule, and imported rules default to monitor. Losing counts biases that decision toward "this rule is quiet" for exactly the hosts that had processing trouble, which is the direction that carries risk: promoting a noisy rule is the alert flood monitor mode exists to prevent.

## What changes

- The engine returns the tally alongside an error instead of discarding it. It cannot tell an ordinary retry from a withdrawal, because only the queue knows, so it hands the tally over on every path and the processor decides.
- The processor records it when the queue reports that the WHOLE batch was withdrawn. Every other nack still discards it.
- A withdrawal at the graph-building stage records nothing, and this is stated rather than closed. That attempt resolved no matches, and an earlier attempt's were discarded when it was retried; carrying them across attempts means telemetry state in the work queue, or per-replica state a stateless app tier cannot keep. The requirement says so and a test pins it, so the figure's remaining bias is documented rather than implied away.
- The comparison is against the batch rather than against zero, because the withdrawal predicate is per row: a partly withdrawn batch leaves rows that are re-claimed and evaluated again, while the tally covers all of them.

Exactly-once needs no coordination between workers. A row moves in-flight to pending to set-aside inside one Nack transaction, and the statement that withdraws it matches only rows the same transaction reset, so a row is reported as withdrawn to exactly one caller however many are nacking.

## Impact

- Affected specs: `observability-instrumentation`
- Affected code: `server/detection/internal/engine/engine.go`, `server/detection/internal/pipeline/processor.go`, `server/detection/api/service.go`
