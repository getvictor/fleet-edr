# M12 scale-test harness

UAT plan milestone M12 (see `ai/uat/plan.md` and `docs/testing-strategy.md`). Fans out N simulated EDR hosts against one
server for D wall-clock duration, records client-observed POST /api/events latency, and asserts the documented pass criteria.

The harness exists in two shapes:

| Shape | Where | When |
|---|---|---|
| Per-PR smoke (5 hosts x 5s) | `scale_test.go` (`-tags=integration`) | every PR via `task test:go:server:coverage`'s `./test/scale/...` glob |
| Opt-in long-form run | `scaledriver/` (`go run` via `task uat:scale`) | manual; baseline capture; release-candidate |

Both share the runner at `runner.go` so the smoke test exercises the same code path the long-form lane uses.

## Pass criteria

Per the plan's M12 row:

- `latency_p99 < 250ms` against the developer machine baseline run.
- `error_count == 0` (no HTTP 4xx/5xx, no client-side timeouts).
- `observation_count > 0` (the lane actually ran).

If any criterion fails, the driver exits 2 and the JSON report's `pass` field is `false`. Per-host breakdowns (last error,
per-host observation count, per-host p99) are preserved under `per_host` so a single bad node does not look identical to a
systemic regression.

## Quick start

```bash
# Start the server and a fresh MySQL.
task db:up
task dev:server

# In another shell, export EDR_ENROLL_SECRET from your current session (or
# from a secret manager such as `op read ...`). Avoid scraping shell profile
# files: the secret should live in your session env, not in a checked-in
# rcfile path you can be parsed later.
export EDR_ENROLL_SECRET=...   # paste from your secret source

# dev:server uses mkcert; either trust the cert system-wide (`task dev:certs`)
# OR opt in to TLS skip via `-- --insecure-tls=true`. The default is to verify.
task uat:scale -- --hosts=10 --duration=30s --insecure-tls=true     # smoke
task uat:scale -- --insecure-tls=true                               # 100 hosts x 5 min
task uat:scale -- --duration=30m --insecure-tls=true \
    --output=test/scale/baselines/baseline.json                     # full 30 min baseline
```

The driver inherits `EDR_ENROLL_SECRET` from the environment so the same value the server reads at boot drives the test
agents. If the secret is missing the driver exits 1 with a clear error.

## Scenario mix

- 80% of hosts run `test/fakeagent/scenarios/quiet-host.yaml` on a 5-second jittered cadence (noise floor).
- 20% of hosts round-robin across a curated subset of the L6 corpus (`test/efficacy/corpus/T*/scenario.yaml`) on a
  1-second jittered cadence. Currently `T1059-suspicious-exec`, `T1543.001-launchagent-persistence`,
  `T1548.003-sudoers-tamper`, `T1555.001-keychain-dump`.

Both ratios and the scenario lists are flags (`--quiet-ratio`, `--active-scenarios`); the defaults match the M12 plan
exactly. The +/- 25% jitter applied to each gap de-synchronises hosts so the server does not see a heartbeat-shaped fan-in.

## Output

The report on stdout is JSON-encoded `scale.Report` (see `runner.go`). Key fields:

```json
{
  "start_time": "...", "end_time": "...", "duration": "5m0s",
  "host_count": 100, "quiet_host_count": 80, "active_host_count": 20,
  "observation_count": 32140, "error_count": 0,
  "latency_p50": "12ms", "latency_p95": "38ms", "latency_p99": "61ms",
  "latency_max": "412ms", "observations_per_sec": 107.13,
  "pass": true, "pass_p99": "250ms",
  "per_host": [{ "host_id": "...", "scenario": "...", "observation_count": ..., "latency_p99": "..." }]
}
```

Per-host scenarios show the YAML file path so a regression localised to one scenario family is easy to spot.

## Baseline files

`test/scale/baselines/baseline.json` is the canonical baseline a contributor captures on a representative developer machine.
The plan's pass-criteria-tightening loop is: capture baseline -> compare against last commit -> file a follow-up when the
p99 drifts > 10% upward. The baseline is hand-committed; the driver does not auto-update it.

## What this layer does NOT do

- **Queue depth on the agent**: v1 bypasses the M2 queue + uploader entirely by using `fakeagent.PostDirect`. A v2 lane
  that drives `headless.Run` per host and polls `/state` for queue depth is a future iteration; the v1 measurement target
  is the server's ingest p99 under fan-in, which the direct POST path measures honestly.
- **MySQL CPU / row count growth**: the plan calls for these as observability outputs. They are not gates today;
  capturing them is an operator job during the baseline run (a SigNoz dashboard or `mysqladmin extended-status` snapshot).
  Promote to gates when a regression case justifies them.
- **SigNoz cross-check**: client-observed latency is the gate. A future enhancement can pull server-side
  `http.server.duration` p99 from SigNoz via its query API and compare.
