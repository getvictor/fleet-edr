# Scale-test baselines

Two canonical M12 scale-test baselines captured on a representative developer machine. Each file is a `scale.Report` (see `test/scale/runner.go`); the `per_host` array is dropped from committed baselines because it changes every run (random host UUIDs). Strip with `jq 'del(.per_host)' baseline-X.json > /tmp/b.json && mv /tmp/b.json baseline-X.json` before committing.

| File | Mode | Measures | Regenerate |
| --- | --- | --- | --- |
| `baseline-direct.json` | direct | Server-side ingest p99 under fan-in (each host POSTs to `/api/events` directly) | `task uat:scale -- --duration=30m --insecure-tls=true --output=test/scale/baselines/baseline-direct.json` |
| `baseline-headless.json` | headless | Agent-side queue depth under fan-in (each host runs `headless.Run`; runner polls `/state` for queue_depth) | `CGO_ENABLED=0 task uat:scale -- --mode=headless --duration=30m --insecure-tls=true --output=test/scale/baselines/baseline-headless.json` |

Run against an idle `task dev:server` with mkcert TLS skip enabled (`--insecure-tls=true`). The headless run requires `CGO_ENABLED=0` on macOS because the headless package is gated `!darwin || !cgo`; Linux runs natively.

## Pass criteria reflected in the baselines

- **Direct**: `latency_p99 < 250ms` (plan target), `error_count == 0`, `observation_count > 0`. The `latency_*` fields are populated; `queue_depth_*` are zero (direct mode bypasses the queue).
- **Headless**: `error_count == 0`, `observation_count > 0`, and optionally `queue_depth_max < pass_max_queue_depth` when the operator passes `--pass-max-queue-depth=N`. The `latency_*` fields are 0 by design: per-envelope client latency is meaningless through the queue, so the latency story lives in the SigNoz cross-check (`--signoz-url=http://localhost:8080`) which records `server_latency_p99` + `client_server_delta_p99` when enabled.

## Triage workflow

When a future scale run drifts past the committed baseline, the live `per_host` array (kept in the report on disk but stripped from the committed file) is the first triage tool. Re-run with the same flags + a different `--output`, then `jq '.per_host[] | select(.latency_p99 > <baseline_p95>)'` to find the laggard hosts.
