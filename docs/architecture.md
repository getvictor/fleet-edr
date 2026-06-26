# Architecture

This document describes the Fleet EDR system architecture for developers getting familiar with the codebase.

## Overview

Fleet EDR is a macOS Endpoint Detection and Response system. It captures process lifecycle events and network connections in real time, builds a per-host process graph, runs behavioral detection rules against the graph, and presents findings through a web UI with response capabilities.

```text
┌─────────────────── macOS endpoint ───────────────────┐
│                                                       │
│  ┌──────────────┐  ┌──────────────┐                  │
│  │  ESF System   │  │  Network     │                  │
│  │  Extension    │  │  Extension   │                  │
│  │  (Swift)      │  │  (Swift)     │                  │
│  └──────┬───────┘  └──────┬───────┘                  │
│         │ XPC              │ XPC                      │
│         └────────┬─────────┘                          │
│                  │                                     │
│         ┌────────▼────────┐                           │
│         │   Go Agent      │                           │
│         │   - SQLite queue│                           │
│         │   - Uploader    │                           │
│         │   - Commander   │                           │
│         └────────┬────────┘                           │
└──────────────────│────────────────────────────────────┘
                   │ HTTPS (POST /api/events)
                   │
┌──────────────────│──── Server ────────────────────────┐
│         ┌────────▼────────┐                           │
│         │  Ingest Handler │                           │
│         └────────┬────────┘                           │
│                  │                                     │
│         ┌────────▼────────┐                           │
│         │     MySQL       │                           │
│         │  events table   │                           │
│         └────────┬────────┘                           │
│                  │ poll unprocessed                    │
│         ┌────────▼────────┐                           │
│         │   Processor     │                           │
│         │  ┌────────────┐ │                           │
│         │  │Graph Builder│ │  processes table          │
│         │  └────────────┘ │                           │
│         │  ┌────────────┐ │                           │
│         │  │ Detection  │ │  alerts table             │
│         │  │ Engine     │ │                           │
│         │  └────────────┘ │                           │
│         └─────────────────┘                           │
│                                                       │
│         ┌─────────────────┐                           │
│         │   REST API      │◄──── React UI             │
│         │   /api/*        │      (embedded)           │
│         └─────────────────┘                           │
└───────────────────────────────────────────────────────┘
```

## On-device components

### ESF system extension (`extension/edr/extension/`)

A Swift system extension that subscribes to the macOS Endpoint Security Framework (ESF). Captures four event types:

| Event  | What it captures                                                |
| ------ | --------------------------------------------------------------- |
| `exec` | PID, PPID, path, args, UID, GID, code signing metadata, SHA-256 |
| `fork` | Child PID, parent PID                                           |
| `exit` | PID, exit code                                                  |
| `open` | PID, file path, flags                                           |

Events are serialized as JSON (canonical envelope with `event_id`, `host_id`, `timestamp_ns`, `event_type`, `payload`) and broadcast to connected agents via an XPC Mach service registered through `NSEndpointSecurityMachServiceName`.

Key files:

- `ESFSubscriber.swift` -- ES client, event handlers
- `EventSerializer.swift` -- JSON serialization, payload types
- `XPCServer.swift` -- Mach service listener, peer management
- `main.swift` -- entry point, starts XPC server and ES subscriber

### Network extension (`extension/edr/networkextension/`)

A Swift system extension implementing `NEFilterDataProvider` for network connection monitoring. Captures outbound TCP/UDP socket flows with process attribution via audit tokens: the PID plus the kernel PID generation (`pidversion`), so the server can correlate a flow to the exact process generation by identity rather than a time window, immune to PID reuse.

Events produced:

- `network_connect` -- remote address/port, local address/port, protocol, direction, hostname (from SNI), process path, PID, and `pidversion` (kernel PID generation, when the flow carried an audit token)

Also contains a `NEDNSProxyProvider` for DNS query capture (disabled by default). When enabled, it intercepts DNS queries, extracts query name/type, forwards to the upstream resolver, and emits `dns_query` events with response addresses.

The XPC Mach service uses the `NEMachServiceName` from the `NetworkExtension` dict in Info.plist (`group.com.fleetdm.edr.networkextension`), which nesessionmanager registers in the global bootstrap namespace.

Key files:

- `NetworkFilter.swift` -- content filter, flow handling
- `DNSProxyProvider.swift` -- DNS proxy, query forwarding
- `DNSParser.swift` -- RFC 1035 packet parser
- `NetworkEventSerializer.swift` -- JSON serialization
- `XPCServer.swift` -- Mach service listener (shared with NetworkFilter and DNSProxy)
- `ProcessInfo.swift` -- shared audit token extraction

### Host app (`extension/edr/edr/`)

A background-only macOS app that manages system extension lifecycle. It submits activation/deactivation requests via `OSSystemExtensionRequest` and configures the content filter via `NEFilterManager`. CLI interface:

```console
edr activate           # activate both extensions + enable content filter
edr deactivate         # deactivate both extensions
edr enable-filter      # enable content filter only
edr disable-filter     # disable content filter
edr enable-dns-proxy   # enable DNS proxy
edr disable-dns-proxy  # disable DNS proxy
```

### Go agent (`agent/`)

A daemon that bridges the system extensions to the cloud server. Written in Go with a C bridge for XPC communication.

```text
agent/
├── cmd/fleet-edr-agent/   # entry point, goroutine orchestration
├── receiver/              # XPC client (C bridge to Go channels)
├── queue/                 # SQLite WAL queue for crash-safe event buffering
├── uploader/              # HTTP batch uploader with retry
├── commander/             # polls server for commands, executes kill_process
└── proctable/             # in-memory PID table for network event enrichment
```

**Event flow within the agent:**

1. `receiver` connects to extension XPC Mach services
2. Events arrive as raw JSON bytes on Go channels
3. Events are written to SQLite `queue` (survives restarts)
4. `uploader` batches events and POSTs to `/api/events`
5. `commander` polls `/api/commands` and executes responses

The agent runs two parallel receiver loops (ESF + Network), each with exponential backoff reconnection (1s initial, 30s max).

## Server components

The server is a modular monolith split into five bounded contexts under `server/`: `identity`, `endpoint`, `rules`, `response`, and `detection` (ADR-0004). Each context owns an `api/` package (the only surface other contexts may import), a Go-compiler-enforced `internal/` tree, and its own `migrations/` schema (ADR-0009). The event data plane lives almost entirely in the `detection` context; the subsections below trace a batch through it.

### Ingest handler (`server/detection/internal/intake/`)

Stateless agent-facing handler. `POST /api/events` validates required fields (`event_id`, `host_id`, `event_type`, `timestamp_ns`), enforces a 10 MB body limit (`MaxIngestBodyBytes`), and inserts into the `events` table with `INSERT IGNORE` for idempotent deduplication. The same package serves the unauthenticated `/livez` and `/readyz` probes.

A standalone `fleet-edr-ingest` binary (`server/cmd/fleet-edr-ingest/`) runs this handler independently for horizontal scaling.

### Pipeline (`server/detection/internal/pipeline/`)

Composes the background goroutines detection runs continuously. `processor.go` claims a batch of unprocessed `events` rows every `cfg.ProcessInterval` (default 500ms). For each batch:

1. **Graph builder** (`server/detection/internal/graph/builder.go`) materializes process state:

   - `fork` -> creates process record
   - `exec` -> updates path, args, uid, gid, code signing, SHA-256
   - `exit` -> sets exit time and code
   - Handles PID reuse, exec-without-fork, fork-without-exec

2. **Detection engine** (`server/detection/internal/engine/engine.go`) evaluates registered rules against the batch:

   - Persists findings as alerts with event linkage
   - Returns errors on alert persistence failures (batch is retried)

3. Marks events as processed (or unclaims on failure for retry)

A second goroutine (`processttl.go`) force-completes stale processes every `cfg.StaleProcessInterval`.

### Detection rules (`server/rules/internal/catalog/`)

Concrete rules live in the `rules` context and implement `rules/api.Rule`:

```go
type Rule interface {
    ID() string
    Techniques() []string          // MITRE ATT&CK technique IDs
    Doc() Documentation            // operator-facing description + severity
    Evaluate(ctx context.Context, events []Event, gr GraphReader) ([]Finding, error)
}
```

`Evaluate` may walk the historical process graph through `gr` but must not mutate state. The shipped catalog (`suspicious_exec` through `dns_c2_beacon`) is documented in [`detection-rules.md`](detection-rules.md), generated from each rule's `Doc()` by `tools/gen-rule-docs`.

### Persistence (MySQL 8.4, ADR-0005)

Each bounded context owns its own tables in the shared database; there are no cross-context foreign keys (ADR-0004). The data plane (`detection`) owns:

| Table          | Purpose                                                                          |
| -------------- | -------------------------------------------------------------------------------- |
| `events`       | Raw event storage with processed flag for the claim/process/mark cycle           |
| `processes`    | Materialized process state (PID, `pidversion`, path, args, fork/exec/exit times) |
| `alerts`       | Detection findings with deduplication (host_id, rule_id, process_id)             |
| `alert_events` | Links alerts to triggering events                                                |
| `hosts`        | Enrolled-host roster with last-seen / online status                              |

`commands` lives in `response`; `enrollments` in `endpoint`; the `app_control_*` policy tables in `rules`; `users`, `sessions`, `roles`, and `audit_events` in `identity`.

### Read and operator API

These endpoints are session-gated (cookie + CSRF) and back the admin UI. Four contexts expose an `internal/operator/` package; `identity` serves its session, auth, and audit routes from dedicated packages (`login`, `oidc`, `breakglass`, `audit`):

| Endpoint                                                                  | Context   | Returns                                      |
| ------------------------------------------------------------------------- | --------- | -------------------------------------------- |
| `GET /api/hosts`                                                          | detection | Host list with online status                 |
| `GET /api/hosts/{host_id}/tree`                                           | detection | Process forest with children, network events |
| `GET /api/hosts/{host_id}/processes/{pid}`                                | detection | Process detail with network + DNS            |
| `GET /api/alerts`, `GET /api/alerts/{id}`, `PUT /api/alerts/{id}`         | detection | Alert list / detail / status update          |
| `POST /api/commands`, `GET /api/commands/{id}`                            | response  | Operator issues a command + reads its status |
| `GET /api/rules`, `GET /api/attack-coverage`                              | rules     | Rule catalog + MITRE Navigator layer         |
| `/api/v1/app-control/*`                                                   | rules     | Application-control policy CRUD              |
| `GET /api/enrollments`, `POST /api/enrollments/{host_id}/{revoke,rotate}` | endpoint  | Enrollment roster + revoke / rotate          |
| `GET /api/session`, `/api/auth/*`, `GET /api/audit-events`                | identity  | Session, OIDC sign-in, audit log             |

The agent-facing routes authenticate with a per-host token (or the enroll secret for `POST /api/enroll`), not a session: `POST /api/events` (`detection`), `POST /api/enroll` (`endpoint`), and the command channel `GET /api/commands` + `PUT /api/commands/{id}` (`response`) that the agent's commander polls.

### Web UI (`ui/`)

React 19 + TypeScript + Vite + D3.js. Embedded in the Go server binary via `//go:embed`. Served at `/ui/`.

In dev, `task dev:server` sets `EDR_UI_LIVE_DIR=server/ui/dist` so the server reads the bundle from disk instead of the compile-time embedded copy. A `task build:ui` in another terminal is picked up on the next request without a server restart. Production builds leave `EDR_UI_LIVE_DIR` unset and serve the embedded bundle.

Pages:

- **Login**: OIDC sign-in plus break-glass admin redemption (session cookie + CSRF token)
- **Host list**: table of enrolled hosts with event counts
- **Process tree**: D3 hierarchical tree with click-to-select, alert badges
- **Process detail**: side panel with metadata, network connections, DNS queries, kill button, alert status management
- **Alert list**: filterable table with severity badges, status transitions

## Data flow

```text
ESF/NE Extension  ──XPC──►  Agent  ──HTTP──►  Ingest  ──►  MySQL
                                                              │
                                               Processor ◄───┘
                                               │
                                          Graph Builder ──► processes table
                                               │
                                          Detection ──► alerts table
                                               │
                                          Mark processed
                                               │
                                          REST API ◄── React UI
```

Events are immutable once ingested. The processor reads unprocessed events, materializes process state, runs detection, and marks them done. This decoupling means the ingest path has no dependencies on processing speed.

## Code signing and XPC trust model

All on-device binaries are signed with the Victor Lyuboslavsky personal Developer ID team certificate (team ID `FDG8Q7N4CC`). The system extension XPC servers validate connecting peers via `xpc_connection_set_peer_code_signing_requirement`, requiring `anchor apple generic and certificate leaf[subject.OU] = "FDG8Q7N4CC"`.

The agent binary must be signed with `--options runtime` (hardened runtime) for XPC peer validation to work at the kernel level.

## Local development

### Prerequisites

- macOS 26+ with Xcode
- Docker (for MySQL)
- Go 1.26+
- Node.js 22+

### Quick start

```bash
# Start MySQL
docker compose up mysql -d

# Build and run the server (port 33306 for MySQL)
cd ui && npm run build && cd ..
go run ./server/cmd/fleet-edr-server/ -dsn "root@tcp(127.0.0.1:33306)/edr?parseTime=true"

# Open http://localhost:8088/ui/

# Run tests
EDR_TEST_DSN="root@tcp(127.0.0.1:33306)/edr_test?parseTime=true" go test ./server/...
go test ./agent/... ./internal/...
```

### VM testing

For testing with real system extensions, use a macOS VM with SIP disabled and developer mode on. See [`lessons-and-gotchas.md`](lessons-and-gotchas.md) for VM-specific setup notes. The host app must be in `/Applications/` and signed with the Fleet org certificate.
