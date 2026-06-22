# Trim the server and agent configuration surface

## Why

The product is early in its lifecycle and every configuration knob is a standing liability: a validation branch, a documented default, a support question, and a way to misconfigure a security product. An audit of the full surface (server ~51 env vars, agent ~16) found a tier of knobs that no operator sets and no test or deployment depends on: internal loop cadences, batch sizes, queue caps, sampling rates, and one variable (`EDR_HOST_TOKEN_GRACE`) that the self-validating-token model stopped consuming entirely. It also found a duplicate path: the database can be configured either as a single `EDR_DSN` or composed from discrete `EDR_MYSQL_*` parts. Carrying two ways to do one thing, plus a tier of tuning nobody touches, is maintenance cost without operator value.

This change removes the dead, duplicate, and internal-tuning knobs and fixes their values as constants. It deliberately keeps every load-bearing lever: security and compliance controls (session and reauth timeouts, enroll rate limit, break-glass IP allowlist and bootstrap-token TTL, OIDC JIT provisioning and default role), the detection false-positive allowlists, and documented operational levers (`EDR_SHUTDOWN_DRAIN`, agent `EDR_PROCESS_RECONCILE_INTERVAL`). The detection allowlists are kept but flagged for a follow-up that moves them to a DB/policy-backed layer (they are the wrong shape for env-var CSVs on a stateless multi-replica server); that follow-up is tracked as a separate issue.

## What changes

- **Removed server env vars (17), now fixed constants or unsupported:**
  - Dead: `EDR_HOST_TOKEN_GRACE` (no longer consumed by the self-validating-token model).
  - Duplicate: `EDR_MYSQL_ADDRESS` / `EDR_MYSQL_USERNAME` / `EDR_MYSQL_PASSWORD` / `EDR_MYSQL_DATABASE` and the compose-from-parts path. `EDR_DSN` (or `EDR_DSN_FILE`) is the only supported database configuration.
  - Security-positive: `EDR_TLS_ALLOW_TLS12`. The TLS floor is now unconditionally TLS 1.3 (the only client is the project's own modern Go agent).
  - Internal tuning, fixed as constants: `EDR_PROCESS_INTERVAL`, `EDR_PROCESS_BATCH`, `EDR_RETENTION_INTERVAL`, `EDR_STALE_PROCESS_TTL`, `EDR_STALE_PROCESS_INTERVAL`, `EDR_HOST_TOKEN_LIFETIME`, `EDR_AUDIT_READ_SAMPLING`, `EDR_AUDIT_ASYNC_QUEUE_CAP`, `EDR_OIDC_SCOPES`, `EDR_OIDC_STATE_COOKIE_TTL`, `EDR_BREAKGLASS_RP_DISPLAY_NAME`.
- **Removed agent env vars (5), now fixed constants:** `EDR_BATCH_SIZE`, `EDR_UPLOAD_INTERVAL`, `EDR_PRUNE_AGE`, `EDR_NETWORK_COALESCE_WINDOW`, `EDR_AGENT_QUEUE_MAX_BYTES`. The queue byte cap is still enforced at its fixed 500 MiB value; the coalescing window stays a fixed 10s, deliberately under the 30s beacon-correlation window.
- **Component constructors keep their parameters.** Only the env-var and config-struct surface is removed; `cmd/main` now passes the default constant at each call site, so integration tests that inject explicit values through the bootstrap `Deps` / `Options` structs are unaffected.
- **A removed variable is inert.** Setting one is ignored at boot rather than an error, so a stale deployment config does not take a deployment down.

## Kept deliberately (load-bearing; not in scope)

`EDR_SHUTDOWN_DRAIN`, `EDR_ENROLL_RATE_PER_MIN`, `EDR_OIDC_ALLOW_JIT_PROVISIONING`, `EDR_OIDC_DEFAULT_ROLE`, `EDR_BREAKGLASS_BOOTSTRAP_TOKEN_TTL`, `EDR_BREAKGLASS_IP_ALLOWLIST`, `EDR_SESSION_*`, `EDR_BREAKGLASS_SESSION_*`, `EDR_REAUTH_WINDOW`, `EDR_RETENTION_DAYS`, the four detection allowlists, `EDR_DISABLED_RULES`, `EDR_TRUSTED_PROXIES`, and agent `EDR_PROCESS_RECONCILE_INTERVAL`. These are security/compliance levers, false-positive controls, or documented operational levers, and several are relied on by the E2E suite and the docker demo.

## Not in this change

- Moving the four detection allowlists (and any other env-CSV configs that are the wrong layer for a stateless server) to a DB/policy-backed surface. Tracked as getvictor/fleet-edr#459.
- Any change to the kept knobs' behavior or defaults.
