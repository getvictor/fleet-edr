# Configuration surface review

**Cadence:** quarterly **Time budget:** 60-90 min **Trigger mode:** manual

## Why this matters

Every configuration knob (server env var, agent env var, conf-file key, launchd plist override, mobileconfig managed pref) is a standing liability: a validation branch, a documented default, a support question, and a way to misconfigure a security product. Knobs accumulate silently. A feature adds three env vars "for flexibility"; a refactor stops consuming one but leaves it parsed; a value that should be a fixed constant ships as a tunable because it was easier at the time. None of this is visible to a compiler or linter: a parsed-but-unused env var compiles and passes every CI gate.

The product is early and deliberately keeps the surface small (see the `trim-config-surface` change and `server-configuration` / `agent-configuration` specs). This sweep keeps it small. Three failure modes it targets:

1. **Dead knobs.** Parsed and documented but no longer read by any consumer (the `EDR_HOST_TOKEN_GRACE` shape: the code comment even said "no longer consumed" for weeks before removal).
2. **Wrong-layer knobs.** State that rides an env-var CSV when it belongs in MySQL/policy on a stateless multi-replica server (the four detection allowlists are the live example: an operator edits them, restarts every replica, and they still can't change them per-host). These need a restart to change and break the stateless-server invariant (ADR-0010).
3. **Knobs that should be constants.** Internal tuning (loop cadences, batch sizes, sampling rates, queue caps) exposed as operator knobs that no operator sets and no deployment depends on. Each one is parse + validate + doc + test surface for zero operator value.

## Scope

- Server: `server/config/config.go` (env vars, defaults, `loadFrom` helpers).
- Agent: `agent/config/config.go`, `agent/config/conffile.go`, the launchd plist under `packaging/`, and any mobileconfig managed prefs.
- Docs that enumerate knobs: `docs/install-server.md`, `docs/operations.md`, `docs/okta-setup.md`, `docs/breakglass.md`, `docs/threat-model.md`, `docs/quickstart-vm.md`.
- Deploy artifacts that set knobs: `docker-compose*.yml`, `Taskfile.yml`, `scripts/*.sh`, `packaging/`.

## Steps

### 1. Build the live inventory

Enumerate every config option actually read by the code:

- Server: `grep -nE 'getenv\("EDR_|"EDR_[A-Z_]+"' server/config/config.go`.
- Agent: same over `agent/config/`.
- Cross-check the struct fields against their consumers: for each field, `grep -rn '\.<Field>' server agent --include='*.go' | grep -v _test`. A field with no non-test consumer is a **dead knob** candidate.

### 2. Classify each knob

For each live knob, ask the two questions that decide its fate:

- **Is it load-bearing?** Does a test, the docker demo, or the E2E suite (`scripts/test-e2e-coverage.sh`) set it? Does a documented deployment depend on it? If yes, keep it (removing it breaks something real).
- **Is it a genuine operator lever?** A security/compliance control (session timeouts, rate limits, break-glass gating), a deployment-shape setting (DSN, listen addr, TLS, proxy), or a documented operational lever (retention days, shutdown drain, heartbeat interval)? If yes, keep it.

Anything that is **neither** load-bearing nor a genuine lever is a removal candidate: fix the value as a constant, keep the consumer's parameter for test injection, and pass the constant at the `cmd/main` call site.

### 3. Flag wrong-layer knobs

For each kept knob, ask whether an env-var CSV is the right shape. A knob that an operator would reasonably want to change per-host, change without a restart, or have differ across replicas does not belong in boot-time env on a stateless server (ADR-0010). File an issue to move it to MySQL/policy; do not attempt the migration inside this sweep (refuse compounded scope).

### 4. Cross-check docs and deploy

For every removed or renamed knob, scrub `docs/`, `docker-compose*.yml`, `Taskfile.yml`, `scripts/`, and `packaging/`. A knob removed from code but left in a docs table or a compose file is worse than no docs: it tells an operator to set something inert.

### 5. Ship the delta

A real removal is a behavior change: it ships an `openspec/changes/<name>/` proposal + delta against `server-configuration` / `agent-configuration`, per `CLAUDE.md`. A removed variable must be **inert** (ignored at boot), never a hard error, so a stale deployment config does not take a deployment down.

## Definition of done

One of:

- A PR that removes dead/duplicate/should-be-constant knobs (with the OpenSpec delta and docs/deploy scrub), OR
- One or more issues filed for wrong-layer knobs that need a DB/policy migration, OR
- A dated "no changes" line appended to [`../log.md`](../log.md) recording that the surface was reviewed and is clean.

Never leave a dead or wrong-layer knob in place silently: it must end as a removal, a filed issue, or a written-down clean finding.
