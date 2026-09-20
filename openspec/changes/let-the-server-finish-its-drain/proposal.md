# Deployments must let the server finish the drain they depend on

Issue #1127, which was filed against a symptom. The symptom was that spans ending during shutdown never reached the collector. The cause is that the server is killed part-way through its shutdown in every deployment this repository ships, and the lost telemetry is the smallest of the things that costs.

## Measured

`EDR_SHUTDOWN_DRAIN` defaults to 30s and `httpserver.ShutdownTimeout` is 15s, so a graceful stop needs up to 45 seconds: 30s serving with `/readyz` at 503 so the load balancer pulls the replica, then up to 15s draining in-flight requests, then the OTel flush.

No compose file in this repository sets `stop_grace_period`, and Docker's default is 10 seconds. So `docker compose up -d`, `restart`, `down` and the documented rolling upgrade all send SIGTERM, wait 10s, and SIGKILL the server 20 seconds into a 30-second drain.

Confirmed on the dev server by sending SIGTERM by hand and letting it run:

```
09:00:05 shutdown starting  reason="context canceled" drain=30s
09:00:35 shutdown complete
```

Thirty seconds, and only then the flush. Under the harness that found #1127, which waited ten, the process never reached `control.Stop()`, never reached `srv.Shutdown()`, and never reached the flush. Given the full window, the spans arrive: the `Connect` spans for both connected hosts were recorded with `control connection closed: gateway shutting down`, which is what #1127 said was missing.

## What this actually costs

Losing the shutdown telemetry is the visible part. The rest is what the drain exists for:

- **The load balancer never sees the full 503 window.** The drain is the mechanism behind the rolling upgrade that `docs/operations.md` calls hitless and the 99.9% control-plane target in `docs/install-server.md`. Cutting it at ten seconds leaves the LB routing to a replica that is about to vanish.
- **In-flight requests are cut rather than drained.** `srv.Shutdown` never runs.
- **Long-lived control streams are killed rather than ended.** `control.Stop()` never runs, so agents discover the loss by timeout rather than being told to reconnect.

## What changes

- **Every compose file that runs the server declares `stop_grace_period: 60s`**: the prod, quickstart and demo stacks, and the multi-replica stack where the rolling upgrade actually happens. Sixty rather than forty-five so the window is not exactly the deadline it is meant to cover.
- **A test ties the YAML to the Go constants.** `test/arch` now fails when a compose service running the server image grants less time than `EDR_SHUTDOWN_DRAIN` plus `ShutdownTimeout`. Raising the drain without raising the grace period is the regression this prevents, and nothing else would notice it.
- **Operator documentation says it.** The rolling-upgrade procedure claims Compose "waits", which is only true once this is set, and operators running the server anywhere else need the same allowance: `terminationGracePeriodSeconds` on Kubernetes, `TimeoutStopSec` under systemd.

## Why not shorten the drain instead

Because 30s is chosen for the load balancer's benefit, not the server's: it has to outlast the LB's health-check interval so the 503 is observed before the listener closes. Shortening it to fit a 10-second default would break the thing it exists for. The deployment is what should grant the time.

## Out of scope

- Any change to the shutdown sequence or its durations.
- Making the server detect that it is about to be killed. It cannot, and a process that is SIGKILLed has no say.
