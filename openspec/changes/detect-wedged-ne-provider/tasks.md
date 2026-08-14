# Tasks

## 1. Measure before choosing thresholds

- [x] 1.1 Bucket the dogfood host's archive at 10 minutes over 30 days and separate benign silence from the known wedge
- [x] 1.2 Establish the per-stream distributions (DNS-only, connection-only, both) to decide whether the check is per provider or per extension
- [x] 1.3 Confirm the process-activity gate alone separates the populations, so no per-host baseline is needed

## 2. Telemetry-freshness read

- [x] 2.1 Add `TelemetryActivityForHosts` to the visibility `EventArchive`, counting each stream over two nested windows in one grouped query
- [x] 2.2 Uphold the absence contract: a host with nothing in the reference window is omitted, never returned as zeroes
- [x] 2.3 Mirror it in the in-memory archive, absence contract included, and add read-failure injection
- [x] 2.4 Integration test against real ClickHouse: counting, window nesting, host filtering, absence, empty input

## 3. Derivation

- [x] 3.1 New `telemetryhealth` package holding the pure predicate, the two window constants, and the rollup fold
- [x] 3.2 Table-driven tests for every gate, including the idle, offline, and never-produced non-accusation cases
- [x] 3.3 Pin the constants against the measurement so a later edit has to re-derive them

## 4. Read paths

- [x] 4.1 Fold derived conditions into the host health detail, carrying them in their own field
- [x] 4.2 Fold the effective rollup into the host list, one archive query per page
- [x] 4.3 Degrade to reported health when the archive read fails
- [x] 4.4 Integration test both read paths together, plus the archive-outage path

## 5. Operator surface

- [x] 5.1 Render derived conditions alongside the agent's own in the host Details popover
- [x] 5.2 Suppress the relative age for conditions that carry no transition instant
- [x] 5.3 UI tests for the derived rendering, the suppressed age, and the nothing-derived case

## 6. Live QA on the VM

- [ ] 6.1 Confirm no derived condition during normal operation, including a period with genuinely no network activity
- [ ] 6.2 Induce the wedge shape and confirm the host surfaces as degraded naming the provider
- [ ] 6.3 Confirm the signal clears once flow telemetry resumes
- [ ] 6.4 Confirm an offline host is not reported under this condition

## 7. Follow-up

- [ ] 7.1 File the agent-side change to publish the per-provider liveness map to the server, which removes the reference-window ceiling and lets the provider be named from the health claim rather than inferred from the silent stream
