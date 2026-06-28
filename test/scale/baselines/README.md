# Scale-test baselines

Two canonical M12 scale-test baselines captured on a representative developer machine. Each file is a `scale.Report` (see `test/scale/runner.go`); the `per_host` array is dropped from committed baselines because it changes every run (random host UUIDs). Strip with `jq 'del(.per_host)' baseline-X.json > /tmp/b.json && mv /tmp/b.json baseline-X.json` before committing.

| File | Mode | Measures | Regenerate |
| --- | --- | --- | --- |
| `baseline-direct.json` | direct | Server-side ingest p99 under fan-in (each host POSTs to `/api/events` directly) | `task uat:scale -- --duration=30m --insecure-tls=true --output=test/scale/baselines/baseline-direct.json` |
| `baseline-headless.json` | headless | Agent-side queue depth under fan-in (each host runs `headless.Run`; runner polls `/state` for queue_depth) | `CGO_ENABLED=0 task uat:scale -- --mode=headless --duration=30m --insecure-tls=true --output=test/scale/baselines/baseline-headless.json` |
| `post-535-500host.json` | direct | Single-replica server-processing backlog at 500 hosts after #535 (batched graph builder + intra-replica concurrency) and #544 (deadlock-resilient claim) | `EDR_ENROLL_SECRET=dev-enroll-secret task uat:scale -- --hosts=500 --duration=5m --insecure-tls=true --pass-p99=5s --backlog-dsn="root:@tcp(127.0.0.1:33306)/edr?parseTime=true" --pass-max-server-backlog=5000 --output=test/scale/baselines/post-535-500host.json` |

Run against an idle `task dev:server` with mkcert TLS skip enabled (`--insecure-tls=true`). The headless run requires `CGO_ENABLED=0` on macOS because the headless package is gated `!darwin || !cgo`; Linux runs natively.

## Pass criteria reflected in the baselines

- **Direct**: `latency_p99 < 250ms` (plan target), `error_count == 0`, `observation_count > 0`. The `latency_*` fields are populated; `queue_depth_*` are zero (direct mode bypasses the queue).
- **Headless**: `error_count == 0`, `observation_count > 0`, and optionally `queue_depth_max < pass_max_queue_depth` when the operator passes `--pass-max-queue-depth=N`. The `latency_*` fields are 0 by design: per-envelope client latency is meaningless through the queue, so the latency story lives in the SigNoz cross-check (`--signoz-url=http://localhost:8080`) which records `server_latency_p99` + `client_server_delta_p99` when enabled.

## Post-#535 single-replica 500-host baseline (`post-535-500host.json`)

Captures the win from #535 (batch the per-event graph-builder DB round-trips + intra-replica processor concurrency) and #544 (deadlock-resilient claim), measured with the `--backlog-dsn` server-backlog gate that #203 calls for. The load-bearing number is `server_backlog_*`: the `event_queue` processing backlog stayed bounded at **p99 17, max 17** over the 5-minute 500-host run, versus the pre-#535 linear climb to ~37k that motivated the work. Ingest `latency_p99` was ~18ms and the server logged zero 5xx and (post-#544) zero `claim` deadlocks.

`pass` is `false` for one reason only: `error_count` counts `enroll: context deadline exceeded` from the per-IP enrollment rate limit (30/min) when all 500 simulated hosts dial `/api/enroll` from a single `127.0.0.1`. That is a single-box harness artifact, not a server fault: in a real deployment the 500 hosts come from 500 distinct source IPs. Every host still enrolled on retry and posted its full observation stream; the backlog and latency numbers are unaffected. A pristine `pass:true` 500-host baseline requires the isolated scale lane (separate load-generator hosts) tracked in #203; this file records the single-replica processing-throughput result that the merged work delivers.

## Triage workflow

When a future scale run drifts past the committed baseline, the live `per_host` array (kept in the report on disk but stripped from the committed file) is the first triage tool. Re-run with the same flags + a different `--output`, then `jq '.per_host[] | select(.latency_p99 > <baseline_p95>)'` to find the laggard hosts.
