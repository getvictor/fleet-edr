# Industry best practices checklist

A living self-audit of the practices, tools, and standards a best-in-class open-source EDR
should adopt. Items are checked when this repo already implements them and unchecked when
they are deliberate gaps or future work.

The point is honest comparison against vendors like CrowdStrike, SentinelOne, and Elastic
Security on one hand, and exemplar open-source projects (Kubernetes, Sigstore, Falco,
Fleet, Wazuh, osquery) on the other. Update as the project evolves; do not delete
unchecked items.

Legend: `[x]` adopted, `[ ]` not yet, `[~]` partially adopted (note in the rationale),
`[-]` will not do (rationale required).

---

## 1. EDR detection content and response

The detection surface is the product. Treat detection content as code: versioned, reviewed,
testable, and mapped to a public taxonomy.

- [x] Behavioral detection rule engine (Go, runs against materialized process graph: see
  `server/detection/`)
- [x] Code-signing capture on every `exec` event (team identifier, signing flags, hash)
- [x] SHA-256 hashing of executed binaries
- [x] Network-attribution events (PID -> connection) via `NEFilterDataProvider`
- [x] Server-driven blocklist policy with versioning (`policies` table, agent diffs by
  version)
- [x] Response action: command queue (kill, block) with ack/complete lifecycle
- [ ] **MITRE ATT&CK mapping** on every rule (technique IDs as rule metadata, surfaced in UI
  and exports). Required to talk to SOCs.
- [ ] **Sigma rule support** (import community rules; transpile to native rule format)
- [ ] **YARA scanning** for file-based detections (signature + heuristic)
- [ ] **IOC management**: bulk import of hashes / domains / IPs from STIX/TAXII feeds
- [ ] **Threat-intel enrichment**: VirusTotal, AlienVault OTX, GreyNoise lookups on alert
- [ ] **File quarantine** with cryptographic chain of custody (move to vault, hash before
  and after, signed manifest)
- [ ] **Network isolation** action (deny all but management traffic to a single host)
- [ ] **Memory acquisition** for forensics on demand
- [ ] **DNS query monitoring** (the `dns-monitoring.md` doc exists but the data plane
  is not yet wired through ESF / NE)
- [ ] **USB / removable-media device events**
- [ ] **File integrity monitoring** (FIM) for sensitive paths
- [ ] **Persistence-mechanism coverage**: LaunchAgents (have), LaunchDaemons, login items,
  cron, sudoers, kernel extensions, browser extensions
- [ ] **Tamper resistance**: agent self-protection (block `kill -9` of agent, detect launchd
  unload, signed-config enforcement)
- [ ] **Offline buffering with bounded loss** documented + tested (SQLite queue exists;
  needs explicit drop policy + metric)
- [ ] **Detection content repository** separate from engine (community PRs land in `rules/`
  with test fixtures, like Falco rules or Sigma)
- [ ] **Detection unit tests with replayed event fixtures** (golden-event suites per rule)
- [ ] **Detection coverage report** mapped to ATT&CK matrix (Atomic Red Team replays,
  Caldera scenarios)
- [ ] **Behavioral baselining / anomaly detection** (statistical or ML; even simple
  per-host process-frequency baselines)
- [ ] **Threat-hunting query interface** (saved queries against the process graph; long-term
  this becomes a SQL or KQL-style surface)
- [ ] **Case management**: alert -> investigation -> evidence -> outcome with audit trail
- [ ] **SOAR / playbook integration** (webhook out, structured response API)
- [ ] **SIEM export**: Splunk HEC, Elastic, Syslog/CEF/LEEF formats
- [ ] **Slack / Teams / PagerDuty alert sinks**
- [ ] **OCSF (Open Cybersecurity Schema Framework)** event export. Splunk-led standard
  adopted by AWS Security Hub, Cloudflare, Sumo Logic, IBM QRadar; becoming the lingua
  franca for cross-vendor security telemetry exchange
- [ ] **OpenC2** action verbs for the response API (OASIS standard for `kill`, `isolate`,
  `quarantine`, etc.) so SOAR platforms can drive responses without custom adapters
- [ ] **LOLBAS / GTFOBins** reference data baked into rules so each detection cites the
  living-off-the-land binary entry that justifies the alert
- [ ] **DeTT&CT / ATT&CK Navigator export** for visualizing rule-set coverage against the
  matrix; lets buyers compare your coverage to commercial vendors
- [ ] **Atomic Red Team / Stratus Red Team / Caldera** scenario replays in CI to assert
  rules fire on canonical attack signals
- [ ] **ITDR signals** -- pull IdP login anomalies, privileged-access changes, and
  lateral-movement indicators into the same alert surface (Okta, Entra ID system logs).
  EDR / ITDR convergence is a 2024-2026 industry trend
- [ ] **Deception primitives** -- canary tokens, honeyfiles, honey credentials. Cheap,
  high signal-to-noise, and a differentiator for an open-source EDR

## 2. Cross-platform reach

Today the agent is macOS-only on Apple Silicon. Best-in-class EDRs (CrowdStrike Falcon,
SentinelOne, Microsoft Defender for Endpoint, Elastic Security, Wazuh) run one server
that ingests from OS-specific agents and presents a unified host inventory, event schema,
process-graph format, and alert queue. The agent is per-OS because the telemetry sources
differ (ESF on macOS, eBPF / `auditd` on Linux, ETW + kernel callbacks on Windows), but
everything past the upload boundary is platform-agnostic. Achieving that means the event
envelope, host identity model, and detection-rule API have to be designed without macOS
assumptions baked in.

- [x] macOS 13+ on Apple Silicon (system extension + network extension + agent)
- [-] macOS Intel -- **will not do**. Apple stopped shipping Intel Macs in 2023; the last
  supported macOS release for Intel is approaching EOL. Pilot customers are Apple Silicon
  only, so the QA + signing matrix is not worth carrying.
- [ ] **Linux agent** (eBPF-based; replace ESF with `tracee` / `falco-libs` / direct eBPF)
- [ ] **Windows agent** (ETW + Defender APIs / Windows Driver)
- [ ] **Container runtime telemetry** (Docker / containerd / CRI-O)
- [ ] **Kubernetes-aware** events (pod / node / namespace attribution)
- [ ] **Platform-agnostic event envelope** (today `schema/events.json` mirrors the ESF
  vocabulary; needs an audit before a Linux or Windows agent ships so we do not bake in a
  macOS-shaped contract that future agents have to translate around)
- [ ] **Unified process-graph model** that admits Windows job objects and Linux cgroups,
  not just POSIX `pid`/`ppid`
- [ ] **Per-platform detection-rule selectors** (a rule declares the OS / kernel surface it
  applies to, so the engine skips evaluation on irrelevant hosts)

## 3. Security: AuthN, AuthZ, cryptography

- [x] Argon2id password hashing for users (with random per-user salt)
- [x] Argon2id host-token hashing for enrollment (with deterministic token-id index for
  fast lookup)
- [x] Constant-time comparison for secrets (`subtle.ConstantTimeCompare` for CSRF tokens)
- [x] HTTP-only, Secure, SameSite session cookies (`server/authn/`)
- [x] CSRF protection on unsafe methods (per-session token in header)
- [x] Bearer-token authentication for agents (`HostToken` middleware)
- [x] Rate limiting on login and enrollment endpoints
- [x] TLS 1.3 by default; TLS 1.2 only with explicit opt-in for legacy pilots
- [x] Restricted TLS 1.2 cipher suites (forward-secrecy AEAD only)
- [x] HSTS with `includeSubDomains`, two-year max-age
- [x] Reload TLS cert + key on `SIGHUP` without dropping connections
- [x] Refusal of `X-Forwarded-For` until a trusted-proxy allowlist exists
- [x] Audit logging of auth outcomes with span attributes
- [ ] **Multi-factor authentication** (TOTP first, WebAuthn second)
- [ ] **SSO**: SAML 2.0 and OIDC for enterprise identity providers
- [ ] **RBAC** with role definitions (admin, analyst, read-only) and per-route gates
- [ ] **Mutual TLS for agent <-> server** (today is bearer-only; mTLS pins the agent
  identity at the transport layer)
- [ ] **Certificate pinning** in the agent (refuse rotation that bypasses pin)
- [ ] **Secrets management**: integrate with HashiCorp Vault / AWS KMS / GCP KMS for the
  enroll secret and DB DSN
- [ ] **Encryption at rest** for the events table (per-row payload encryption with
  envelope keys, or InnoDB tablespace encryption documented as a deployment requirement)
- [ ] **Audit-log export** to immutable storage (S3 Object Lock, etc.)
- [ ] **Session pinning** to client IP / fingerprint with rotation policy
- [ ] **Account lockout / progressive delay** after failed logins
- [ ] **Password breach check** at set-time (`k-anonymity` against HIBP)
- [ ] **Signed configuration** delivered to agents (policies signed by server key the agent
  pins at install)

## 4. Supply-chain security

This is where the bar has moved fastest. SLSA, Sigstore, OpenSSF Scorecard are the new
floor for any project that wants enterprise adoption.

- [x] SHA-pinned GitHub Actions everywhere (`actions/checkout@<40-char-sha>`)
- [x] `permissions: {}` default at workflow level, narrow per-job grants
- [x] `persist-credentials: false` on every checkout
- [x] `concurrency` cancellation to avoid stale parallel runs
- [x] `zizmor` GitHub Actions security audit (auditor persona, weekly schedule)
- [x] `actionlint` workflow-syntax linter
- [x] `govulncheck` against agent and server (push, PR, dispatch)
- [x] Dependabot for `gomod` (agent + server), `npm` (ui), and `github-actions`
- [x] Dependabot `cooldown` (10 days default, 30 for majors) plus version grouping
- [x] Major-version updates ignored for code deps (security overrides bypass)
- [x] **Sigstore / cosign** signed release artifacts via keyless OIDC: every pkg,
  mobileconfig, SHA256SUMS, SBOM, AND the GHCR server image gets a `.sig` + `.pem`
  on each release tag (`.github/workflows/release.yml`)
- [~] **SLSA Build Level 3** provenance attestations on releases via
  `actions/attest-build-provenance`. We claim **build level 2** in practice — Apple
  notarization breaks SLSA L3's hermeticity requirement (notarytool reaches Apple's
  network). Documented in the workflow comment; revisit if Apple ever offers an
  offline notary path
- [x] **SBOM generation** at build time -- both CycloneDX and SPDX via
  `anchore/sbom-action` (syft underneath), attached to releases. Server image SBOM
  also pushed as a cosign attestation on the registry side
- [x] **OpenSSF Scorecard** workflow + badge in README
  (`.github/workflows/scorecard.yml`)
- [ ] **OpenSSF Best Practices Badge** (CII) -- silver minimum
- [x] **CodeQL** SAST workflow (Go + TypeScript + Swift) at
  `.github/workflows/codeql.yml`
- [ ] **Semgrep** with security rulesets (catches things golangci-lint / ESLint miss)
- [x] **OSV-Scanner** in CI (broader than `govulncheck`; covers indirect npm deps too)
  at `.github/workflows/osv-scanner.yml`
- [ ] **Trivy / Grype** scan of release container images
- [ ] **Verified-commit policy** (signed commits or DCO required on `main`)
- [ ] **Branch protection ruleset** committed as `.github/rulesets/*.json` (so the
  protection lives in the repo, not just the GitHub UI)
- [ ] **Reproducible builds** -- documented `-trimpath`, `-buildvcs`, deterministic
  timestamps, and a `verify-build` job that diffs two independent rebuilds
- [ ] **`go.sum` / `package-lock.json` integrity verification** in CI (`go mod verify`,
  `npm ci` already enforces this for npm)
- [-] **`vendor/` modules** -- **will not do**. `go.sum` + GOPROXY checksum verification
  already gives reproducible, hermetic builds; vendoring would double the diff size of every
  dep bump and slow CI clones for no security gain. Reconsider only if an air-gapped
  customer requires it
- [ ] **GUAC / in-toto attestations** for end-to-end supply-chain provenance
- [ ] **`step-security/harden-runner`** on every GHA job (egress firewall + audit) so a
  compromised dep cannot exfiltrate secrets at build time
- [ ] **OpenSSF Allstar** to enforce repo-settings policies (branch protection, required
  reviews) as code
- [ ] **`SECURITY-INSIGHTS.yml`** (OpenSSF format) -- machine-readable security metadata
  scanners and aggregators consume

## 5. Code quality and static analysis

- [x] `golangci-lint` v2 with a deep linter set: `gosec`, `errcheck`, `errorlint`,
  `staticcheck`, `revive`, `bodyclose`, `sqlclosecheck`, `noctx`, `forbidigo`, `depguard`,
  `usetesting`, `testifylint`, `nilnesserr`, `unused`, `modernize`, ...
- [x] `forbidigo` rules forbidding default-logger calls and `print`/`println`
- [x] `depguard` blocking `github.com/pkg/errors` (stdlib only)
- [x] `staticcheck` "all" with selective opt-outs documented
- [x] `gofmt -s` enforced
- [x] `clang-tidy` + `clang-format` for the CGo bridge (`agent/xpcbridge/`)
- [x] `swiftlint --strict` for the macOS extensions
- [x] TypeScript ESLint with `strictTypeChecked`, `eslint-plugin-security`,
  `eslint-plugin-no-unsanitized`, `react-hooks/exhaustive-deps`, `eqeqeq`,
  `no-explicit-any: error`
- [x] `tsc --noEmit` strict type-check in CI
- [x] SonarCloud for cross-language quality + security hot spots
  (`sonar-project.properties`, dedicated `SonarCloud` workflow)
- [x] Multi-module Go workspace with clear boundaries (`agent/`, `server/`)
- [x] **Test-coverage thresholds** uploaded to SonarCloud. Both Go and TS coverage
  reports flow through (`sonar.go.coverage.reportPaths`,
  `sonar.javascript.lcov.reportPaths`); the "Coverage on New Code" gate is set to
  ≥80% and applies per PR.
- [ ] **Codecov / Coveralls** with PR comments and coverage diff
- [ ] **`go vet -vettool=fieldalignment`** -- catches struct padding waste in hot structs
- [x] **`uber-go/nilaway`** -- inter-procedural nil-dereference static analysis. Catches
  panics that `staticcheck` and `govet -nilness` miss because nilaway tracks nilability
  across function boundaries. Wired as `task lint:nilaway` locally and as a gating CI job
  `.github/workflows/go-nilaway.yml`. False positives from tests or map-aliasing are
  addressed by restructuring the code (explicit `require.NotNil` / `ok :=` guards) rather
  than adding a blanket suppression, so the gate stays honest.
- [ ] **`go-licenses` / `licensed`** to enforce dep license policy
- [ ] **Spell-check** (`codespell`, `misspell`) in CI
- [ ] **Markdown linter** (`markdownlint-cli2`) for the docs
- [x] **Pre-commit hooks** via `lefthook` (`lefthook.yml`) running gofmt, eslint, and
  swiftformat on staged files; pre-push runs `go build`, fast golangci-lint, and `tsc`
- [ ] **`gci` import-grouping** + `goimports` enforced
- [ ] **Go test build tags** to separate integration / e2e / unit
- [ ] **Mutation testing** for the detection engine (`go-mutesting` / Stryker)

## 6. Testing strategy

- [x] Unit tests with race detector (`go test -race -count=1`) for agent and server
- [x] Integration tests against real MySQL 8.4 in CI
- [x] React component tests with Vitest + Testing Library
- [x] Test helpers and shared fixtures (`server/store/testhelper.go`,
  `server/api/testhelpers_test.go`)
- [x] Subtest + table-driven test convention (per `~/.claude/CLAUDE.md`)
- [x] Load-test harness (`test/loadtest.go`)
- [ ] **End-to-end tests** (Playwright / Cypress) covering login -> alert -> ack -> close
- [ ] **API contract tests** -- generated from OpenAPI, run against the live server
- [ ] **Fuzz tests** for the JSON event parser, the policy diff, and any HTTP body that
  comes from the agent (Go has built-in `go test -fuzz`)
- [ ] **Property-based tests** for the process graph builder (`gopter` / `rapid`)
- [ ] **Snapshot tests** for the React process-tree D3 layout
- [ ] **Visual-regression tests** (Playwright screenshots or Chromatic) on UI components
- [ ] **Accessibility (a11y) tests**: `@axe-core/react` in component tests + `pa11y` on
  built pages
- [ ] **Performance budgets** asserted in tests (event-ingest p95 < N ms,
  graph-rebuild < N s for K events)
- [ ] **Chaos / fault-injection** tests (DB drops connection mid-batch, OTLP collector
  unreachable, agent disk full, clock skew)
- [ ] **Load-test in CI** on a schedule with a regression bound
- [ ] **Mutation-testing baseline** to catch over-mocked tests
- [x] **Test coverage measured** via SonarCloud (Go via
  `sonar.go.coverage.reportPaths`, UI via
  `sonar.javascript.lcov.reportPaths`). See §5 for the per-PR ≥80% gate.
- [ ] **Smoke test against macOS VM** in CI (the SIP-disabled VM exists locally; could be
  scripted into a self-hosted runner)

## 7. Observability and operations

The observability stack is unusually strong here for an early-stage project; this is a
genuine differentiator versus most competitors.

- [x] OpenTelemetry SDK wired for traces, metrics, and logs (`server/observability/`,
  `agent/observability/`)
- [x] OTLP/gRPC export with no-op fallback when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset
- [x] W3C `traceparent` + `baggage` propagators installed unconditionally
- [x] `otelhttp` auto-instrumentation on the HTTP server
- [x] `otelsql` instrumentation with `db.client.connection` metrics (idle / in-use / max)
- [x] `otelslog` bridge so structured logs carry trace context
- [x] Atomic provider publish: providers built fully before any global is set
- [x] Resource attributes from env + host + process detectors, plus build-time
  `service.version`
- [x] Custom metrics surface (`server/metrics/`, `agent/metrics/`) with typed methods so
  attribute keys live in one place
- [x] Slow-request access log upgrade above a threshold (default 500 ms)
- [x] `X-Request-ID` echo derived from trace-id (or inbound header)
- [x] Panic recovery middleware that records on the active span and logs full stack
- [x] Liveness (`/livez`) and readiness (`/readyz`) endpoints
- [x] Graceful shutdown with timeout (15 s for HTTP, 5 s for OTel flush)
- [x] Live SigNoz instance for QA (per memory: required for OTel-affecting changes)
- [ ] **SLO / SLI definitions** committed to repo (`docs/slos.md`) with error-budget
  burn-rate alerts
- [ ] **Runbooks** in `docs/runbooks/` keyed by alert name
- [ ] **On-call rotation** documented (PagerDuty / Opsgenie integration)
- [ ] **Continuous profiling** (Pyroscope / Parca / Polar Signals) wired through OTLP
- [ ] **Synthetic monitoring** of the public ingest endpoint (CloudPing-style)
- [ ] **Distributed tracing across agent <-> server** boundary (propagator is installed;
  the agent uploader needs to actually inject `traceparent` on the upload request)
- [ ] **Dashboard-as-code** for SigNoz / Grafana committed to the repo
- [ ] **Log retention + sampling policy** documented per-environment
- [ ] **Crash reporting** for the Swift extensions -- Sentry or an `os_log` -> OTel
  pipeline. (Firebase Crashlytics is the wrong tool here: deprecated for non-mobile and
  Google-account-locked.)

## 8. API and protocol design

- [x] Versioned URL prefix (`/api/`)
- [x] JSON event schema (`schema/events.json` -- consumed by both agent and server)
- [x] Standard JSON error responses with `Cache-Control: no-store` on health endpoints
- [x] Per-route auth-domain composition (public / host-token / session) at registration
  time so the policy is reviewable in `main.go`
- [~] **OpenAPI 3.1 spec** committed at `docs/api/openapi.yaml`, prose overview at
  `docs/api.md`, AND hosted rendering at `/api/docs` via embedded Redoc (D1
  deliverable: zero external network calls, served from `server/api/docs/embed`).
  Still missing: handler/client codegen via `oapi-codegen` /
  `openapi-typescript`, so today the spec and the Go handlers can still drift
  without CI catching it
- [ ] **AsyncAPI 3.0 spec** for the event envelope (the JSON Schema covers payload but not
  the upload contract)
- [x] **OpenAPI lint in CI** -- `@redocly/cli lint` runs on every PR + push at
  `.github/workflows/openapi-lint.yml`. Failures gate the merge
- [ ] **API contract tests** generated from OpenAPI via `schemathesis` (property-based,
  hits a live server, catches handler/spec drift) or `dredd`. Pairs naturally with the
  lint job above
- [ ] **Pagination contract** (cursor-based) with documented limit defaults across all
  list endpoints
- [ ] **Idempotency keys** on the event upload endpoint so retries are safe end-to-end
  (today dedup is by `event_id`; explicit header keeps semantics first-class)
- [ ] **Per-tenant / per-host rate limiting** beyond the per-route limits today
- [ ] **gRPC + Protobuf event upload** as an alternative to JSON for high-volume hosts
- [ ] **Webhook out** for alerts (with retry, signed payload, replay protection)
- [ ] **API deprecation policy** documented (deprecation header + sunset header per RFC
  8594)
- [ ] **Agent <-> server protocol back-compat policy** -- N versions back the server still
  accepts. Without a written policy every protocol bump risks bricking older fleets that
  the customer's MDM has not yet rolled forward
- [ ] **Server-Sent Events / WebSocket alert stream** so the UI does not poll for new
  alerts (today the React app would have to poll)

## 9. Frontend best practices

- [x] React 19 + TypeScript strict mode
- [x] Vite (modern bundler, fast HMR)
- [x] ESLint security plugins (`eslint-plugin-security`, `eslint-plugin-no-unsanitized`)
- [x] Vitest with jsdom + Testing Library
- [x] D3 for visualization (process tree)
- [x] Embedded UI bundle in the server binary via `embed.FS` (single-binary deploy)
- [ ] **Bundle-size budget** asserted in CI (`size-limit`)
- [ ] **Lighthouse CI** or `web-vitals` thresholds
- [ ] **Accessibility audit** (`@axe-core/react`, `pa11y-ci`) and WCAG 2.2 AA target
- [ ] **Storybook** with interaction tests + visual regression
- [-] **i18n** -- **will not do**. SOC analysts work in English; carrying a translation
  pipeline (string extraction, locale review, RTL layout testing) doubles UI surface for
  zero pilot-customer demand. Revisit if a paying customer requires another locale
- [ ] **Dark mode** with system-preference detection
- [ ] **Content Security Policy** header (the embedded UI lets the server send a strict
  CSP; today none is set)
- [ ] **Subresource Integrity** for any third-party scripts (today there are none, which
  is good; assert it stays that way)
- [ ] **Source-map upload** to crash reporter so production errors are debuggable
- [-] **Service worker / offline UX** -- **will not do**. Anti-feature for a real-time SOC
  console: analysts must see live state, and a security tool that "gracefully" hides a
  disconnection is a hazard, not a UX win

## 10. Data layer

- [x] MySQL 8.4 with `parseTime=true`, foreign keys, and unique constraints enforced
- [x] Idempotent migrations with explicit duplicate-error swallowing (`store.go`)
- [x] Indexed lookup paths for hot queries (composite indexes on
  `(processed, host_id, timestamp_ns)`, etc.)
- [x] `FOR UPDATE SKIP LOCKED` for safe parallel processor claiming
- [x] Foreign key cascades that match the lifecycle (`sessions` -> `users` cascade,
  `alerts.updated_by` -> `users` set null)
- [x] `parseTime=true` enforced even when caller forgets it
- [x] Connection-pool stats exposed via OTel
- [x] Retention runner with configurable age (`server/retention/`)
- [x] Local Docker Compose with `mysql_test` for parallel test isolation
- [ ] **Versioned migrations** with a real tool (`golang-migrate`, `goose`, or `sqlc`'s
  built-in migrator); current "in-process idempotent ALTER" approach hits a ceiling around
  rename / drop operations
- [-] **PostgreSQL alternative** -- **will not do**. Supporting two RDBMSes doubles
  migration testing, query tuning, and store-layer surface for a small team. MySQL 8.4
  covers what the data plane needs; customers who require Postgres can stand up a CDC
  bridge via Debezium against the existing MySQL primary
- [ ] **Read-replica support** for the read-heavy UI queries
- [ ] **Logical-replication / CDC outbox** for downstream SIEM / data-lake export
- [ ] **Backup + point-in-time-restore** runbook
- [ ] **Encryption at rest** documented as a deployment requirement (and enforced via
  config validation in production mode)
- [ ] **Schema-change CI gate** (`atlas migrate lint` or `skeema diff --safe`) that flags
  destructive operations before merge -- particularly important once the in-process
  idempotent-ALTER pattern is replaced with versioned migrations
- [ ] **Slow-query log review** runbook
- [ ] **Data retention by event type** (some events should live longer than others; today
  it's a single global window)

## 11. Build, release, packaging

- [x] Build info (`version`, `commit`, `buildTime`) injected via `-ldflags` and surfaced
  in startup logs + OTel `service.version`
- [x] Multi-stage local dev (Docker Compose for MySQL; `go run` for server)
- [ ] **GoReleaser** for cross-arch binary releases with checksums
- [ ] **Notarized signed `.pkg` installer** (per the MVP plan; not yet automated)
- [ ] **Apple Hardened Runtime** entitlements on the agent + extension binaries
- [ ] **Reproducible-build verification** job in CI
- [ ] **Multi-arch container image** for the server (linux/amd64, linux/arm64) signed by
  cosign
- [ ] **Helm chart** + Kustomize overlays for k8s deployments
- [ ] **systemd unit** + RPM / DEB for self-hosted Linux deployments
- [-] **In-product auto-update channel** (Sparkle / custom signed-manifest fetcher) --
  **will not do**. Enterprise endpoint software updates flow through the customer's MDM
  channel (Fleet, Jamf, Kandji, Intune); in-product self-update bypasses change management
  and gets flagged as a finding by some buyers. Sparkle is a consumer-app pattern
- [ ] **Conventional Commits** + `semantic-release` for automated CHANGELOG +
  versioning. Side benefit: clean commit history is far easier for AI assistants to mine
  for context
- [ ] **`CHANGELOG.md`** following Keep a Changelog format
- [ ] **DORA metrics** dashboard (deployment frequency, lead time for changes,
  change-failure rate, MTTR) committed to the repo as queries / dashboards-as-code

## 12. Open-source community signals

These cost almost nothing and disproportionately drive adoption.

- [x] `README.md` with quick-start that actually works
- [x] Architecture document (`docs/architecture.md`)
- [x] Lessons-and-gotchas log (`docs/lessons-and-gotchas.md`)
- [x] Go conventions doc (`docs/go-conventions.md`)
- [x] DNS monitoring design doc (`docs/dns-monitoring.md`)
- [ ] Issue templates at `.github/ISSUE_TEMPLATE/` (bug, story, reliability). Not committed
  yet; slash-skills that reference them (`create-bug`, `create-story`, `create-reliability`)
  live in the user's global `~/.claude/skills/` only.
- [ ] **`LICENSE`** file at the repo root (unclear which license applies today; pick one
  -- MIT, Apache-2.0, AGPL-3.0 are the obvious candidates and the choice signals
  intent to commercial adopters)
- [ ] **`SECURITY.md`** with a coordinated-disclosure mailbox + GPG key + response SLA
- [ ] **`CONTRIBUTING.md`** with build / test / DCO + style pointers
- [ ] **`CODE_OF_CONDUCT.md`** (Contributor Covenant 2.1)
- [ ] **`CODEOWNERS`** for review routing
- [ ] **PR template** with checklist (tests, docs, security review)
- [ ] **`SUPPORT.md`** explaining where to ask questions
- [ ] **GitHub Discussions** enabled for design conversations
- [x] **Architecture Decision Records** at `docs/adr/NNNN-title.md` with template +
  index at `docs/adr/README.md`; seeded with the single-module, Apple-Silicon-only,
  and standalone-product decisions. Add new ones as non-obvious trade-offs land.
- [ ] **Public roadmap** (GitHub Projects or `ROADMAP.md`)
- [ ] **`OWNERS` / governance** doc for once external contributors arrive
- [ ] **Demo video** or live sandbox linked from README
- [ ] **`go.dev` package documentation** with examples (godoc-quality comments are present;
  `pkg.go.dev` rendering deserves a pass)
- [x] **`.editorconfig`** for cross-IDE / cross-AI-tool formatting consistency
- [ ] **`.gitattributes`** for binary handling, line-ending policy, and language-stat
  hints (so GitHub's language bar reflects reality)
- [x] **`.tool-versions`** so the toolchain (Go, Node, golangci-lint, lefthook) is
  pinned and the same locally, in CI, and inside any AI-driven container. Works with
  both `asdf` and `mise`.
- [ ] **Devcontainer (`.devcontainer/devcontainer.json`)** for reproducible local + cloud
  dev environments; also unlocks GitHub Codespaces and gives AI agents a sandbox
- [x] **`Taskfile.yml`** as a self-documenting command runner at repo root; every
  build, test, lint, dev-loop, and runtime QA command is discoverable via
  `task --list`.

## 13. Compliance and privacy

If anyone is going to deploy this against employee endpoints in regulated industries,
these get asked.

- [ ] **Privacy policy** describing what telemetry the agent collects
- [ ] **Telemetry opt-in / configurable redaction** (e.g. argv truncation, hash-only mode
  for paths)
- [ ] **Data-residency statement** (where event data lives, how to keep it in-region)
- [ ] **GDPR / CCPA data-subject-request** runbook (find / export / delete by host_id or
  user_id)
- [ ] **SOC 2** controls documented (audit logging, change management, access review)
- [ ] **CIS Benchmark** / NIST 800-53 control mapping for marketing
- [ ] **HIPAA** considerations (BAA-friendly hosting profile)
- [ ] **Threat model** committed (`docs/threat-model.md`) with STRIDE per component +
  documented mitigations
- [ ] **OWASP ASVS** (Application Security Verification Standard) self-assessment at
  Level 2 for the server, Level 3 for auth-handling code paths
- [ ] **NIST SSDF** (Secure Software Development Framework, SP 800-218) practice mapping
  -- the SBOM / SLSA / Scorecard checklist most enterprise procurement now demands
- [ ] **CISA Secure by Design Pledge** signed; the pledge ships a public roadmap with
  concrete dates which is itself a procurement signal
- [ ] **EU Cyber Resilience Act (CRA)** readiness -- enforced from late 2027; security
  vendors selling into the EU need SBOM + vulnerability handling + signed updates from
  day one. Most of this overlaps with SLSA / SBOM items above; explicit tracking helps
- [ ] **NIS2 Directive** awareness for EU customers (EDR is "essential entity" tooling)

## 14. Operating-system platform hygiene (macOS)

- [x] System extension (not deprecated kext) for ESF
- [x] Network extension (`NEFilterDataProvider`) for connection capture with PID
  attribution
- [x] Ad-hoc signing pipeline documented for SIP-disabled dev VMs
- [x] Endpoint Security entitlement requested explicitly
- [x] CGo bridge linked with `-lbsm` for `audit_token_to_pid/euid/egid`
- [x] Lessons captured for `os.log` redaction, `es_process_t.cwd` differences, etc.
- [ ] **Notarized signed extensions** for production install via MDM
- [ ] **Profile-delivered entitlement consent** (`SystemPolicyAllListConfiguration` payloads)
  pushed via Fleet so end-users do not see a TCC prompt
- [ ] **MDM-managed Full Disk Access** profile for the agent
- [ ] **Privacy Preferences Policy Control** profile in the installer artifact
- [ ] **Hardened runtime** with the minimum entitlement set audited
- [ ] **OSLogStore** historical pull for forensic timeline reconstruction

## 15. AI-assisted engineering

A 2024-2026 industry shift: AI coding assistants (Claude Code, Cursor, Copilot, Aider) are
now a primary authoring surface, AI PR-review bots are mainstream, and product UIs are
increasingly expected to ship LLM features. Each of those creates new conventions and new
attack surfaces.

### Repo conventions for AI assistants

- [~] **Project-level AI assistant config** -- the user has a global `~/.claude/CLAUDE.md`
  and per-topic plans in `claude/<topic>/` (gitignored). A committed project-level
  `CLAUDE.md` (or `AGENTS.md`) would let any contributor or agent start cold without
  needing the global config
- [ ] **`.cursorrules`** and/or **`.github/copilot-instructions.md`** mirrors of the
  same conventions for non-Claude users
- [ ] **MCP servers committed to the repo** -- shared tooling configs (SigNoz, SonarQube,
  Unblocked) so every contributor's AI agent has the same runtime context

### AI-assisted code review

- [~] **AI PR review bot** -- Qodo PR-Agent is configured (`.pr_agent.toml`) but
  deliberately set to manual-only (`pr_commands = []`, `handle_push_trigger = false`).
  Revisit if PR throughput grows
- [ ] **GitHub Copilot code review** enabled at the repo level (free for public repos)
- [ ] **CodeRabbit / Greptile** as a security-leaning second opinion on auth + crypto
  paths
- [ ] **AI-generated PR change-summary** auto-posted (Qodo can do this; today disabled by
  policy)

### Provenance and risk hygiene for AI-generated code

- [x] Per-user policy on `Co-Authored-By` lines (this user: never; documented in
  auto-memory). Worth promoting into `CONTRIBUTING.md` once that file exists so it binds
  external contributors too
- [ ] **DCO sign-off (`Signed-off-by`)** required on PRs -- forces every contributor (human
  or AI) to attest to the DCO terms; doubles as a paper trail for AI provenance and is
  the Linux Foundation's preferred alternative to CLAs
- [ ] **AI-generated code license stance** documented (training-data contamination risk;
  cite OpenSSF AI/ML Working Group guidance + Linux Foundation AI policy)

### Product-side LLM features (forward-looking)

None of these ship today; flagging them as deliberate-future so they are not forgotten
when the product roadmap reaches that horizon. Treat each as a *new attack surface* on
top of a feature spec.

- [ ] **Alert summarization** in the UI ("why did this rule fire? what did the process
  do?")
- [ ] **Threat-hunting copilot** -- natural-language query against the process graph
- [ ] **Detection-rule authoring assistant** (ATT&CK technique -> Go rule scaffold)
- [ ] **Prompt-injection threat model** for any LLM feature shipped. Event payloads,
  alert text, and process arguments are *all attacker-controlled*; an EDR that blindly
  passes them into an LLM context window is the textbook indirect-prompt-injection target
- [ ] **LLM eval suite in CI** (golden-prompt regression tests; hallucination + injection
  resistance) for every shipped LLM feature
- [ ] **OWASP Top 10 for LLM Applications** self-assessment
- [ ] **OpenSSF AI/ML SIG** best-practices alignment

---

## Scoring summary (rough)

A self-graded rubric so the README badge can be honest. `Total` excludes items marked
`[-]` (will not do); partials (`[~]`) count as half.

| Area                              | Adopted | Total | %    |
|-----------------------------------|---------|-------|------|
| Detection content + response      | 6       | 36    | 17%  |
| Cross-platform reach              | 1       | 8     | 12%  |
| AuthN / AuthZ / crypto            | 13      | 25    | 52%  |
| Supply-chain security             | 15.5    | 27    | 57%  |
| Code quality + static analysis    | 14      | 22    | 64%  |
| Testing                           | 7       | 19    | 37%  |
| Observability + operations        | 15      | 24    | 62%  |
| API design                        | 5.5     | 16    | 34%  |
| Frontend                          | 6       | 14    | 43%  |
| Data layer                        | 9       | 17    | 53%  |
| Build / release / packaging       | 2       | 12    | 17%  |
| Community signals                 | 10      | 24    | 42%  |
| Compliance + privacy              | 0       | 13    | 0%   |
| macOS platform hygiene            | 6       | 12    | 50%  |
| AI-assisted engineering           | 2       | 17    | 12%  |

The supply-chain hardening track shipped Sigstore signing (cosign keyless
on every release artifact), CycloneDX + SPDX SBOMs, SLSA build provenance
at level 2 (Apple notarization breaks L3's hermeticity requirement),
OpenSSF Scorecard, and OSV-Scanner alongside the existing govulncheck.
A real SonarCloud coverage gate (≥80% on new code, per PR) closed the
last big code-quality gap. That moved §4 from 37% to 57% and §5 from 59%
to 64%. Hosting Redoc at `/api/docs` plus a Redocly OpenAPI lint job
moved §8 from 25% to 34%.

The remaining big gaps that buyers ask about are CONTRIBUTING.md and the
rest of the §12 community-signals checklist (now unblocked because
LICENSE has shipped), the detection-content surface (ATT&CK mapping is
wired but Sigma / YARA / IOC management still wait for v1.1), and the
AI-era hygiene that enterprise procurement is starting to ask for (CISA
Secure by Design, OWASP LLM Top 10, AI provenance policy).
