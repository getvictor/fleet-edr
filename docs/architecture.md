# Architecture

This document describes the Fleet EDR system architecture for developers
getting familiar with the codebase.

## Overview

Fleet EDR is a macOS Endpoint Detection and Response system. It captures
process lifecycle events and network connections in real time, builds a
per-host process graph, runs behavioral detection rules against the graph,
and presents findings through a web UI with response capabilities.

```
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
│         │   /api/*     │      (embedded)           │
│         └─────────────────┘                           │
└───────────────────────────────────────────────────────┘
```

## On-device components

### ESF system extension (`extension/edr/extension/`)

A Swift system extension that subscribes to the macOS Endpoint Security
Framework (ESF). Captures four event types:

| Event | What it captures |
|-------|-----------------|
| `exec` | PID, PPID, path, args, UID, GID, code signing metadata, SHA-256 |
| `fork` | Child PID, parent PID |
| `exit` | PID, exit code |
| `open` | PID, file path, flags |

Events are serialized as JSON (canonical envelope with `event_id`, `host_id`,
`timestamp_ns`, `event_type`, `payload`) and broadcast to connected agents
via an XPC Mach service registered through `NSEndpointSecurityMachServiceName`.

Key files:
- `ESFSubscriber.swift` -- ES client, event handlers
- `EventSerializer.swift` -- JSON serialization, payload types
- `XPCServer.swift` -- Mach service listener, peer management
- `main.swift` -- entry point, starts XPC server and ES subscriber

### Network extension (`extension/edr/networkextension/`)

A Swift system extension implementing `NEFilterDataProvider` for network
connection monitoring. Captures outbound TCP/UDP socket flows with process
attribution via audit tokens.

Events produced:
- `network_connect` -- remote address/port, local address/port, protocol,
  direction, hostname (from SNI), process path and PID

Also contains a `NEDNSProxyProvider` for DNS query capture (disabled by
default). When enabled, it intercepts DNS queries, extracts query name/type,
forwards to the upstream resolver, and emits `dns_query` events with response
addresses.

The XPC Mach service uses the `NEMachServiceName` from the `NetworkExtension`
dict in Info.plist (`group.com.fleetdm.edr.networkextension`), which
nesessionmanager registers in the global bootstrap namespace.

Key files:
- `NetworkFilter.swift` -- content filter, flow handling
- `DNSProxyProvider.swift` -- DNS proxy, query forwarding
- `DNSParser.swift` -- RFC 1035 packet parser
- `NetworkEventSerializer.swift` -- JSON serialization
- `XPCServer.swift` -- Mach service listener (shared with NetworkFilter and DNSProxy)
- `ProcessInfo.swift` -- shared audit token extraction

### Host app (`extension/edr/edr/`)

A background-only macOS app that manages system extension lifecycle. It
submits activation/deactivation requests via `OSSystemExtensionRequest` and
configures the content filter via `NEFilterManager`. CLI interface:

```
edr activate           # activate both extensions + enable content filter
edr deactivate         # deactivate both extensions
edr enable-filter      # enable content filter only
edr disable-filter     # disable content filter
edr enable-dns-proxy   # enable DNS proxy
edr disable-dns-proxy  # disable DNS proxy
```

### Go agent (`agent/`)

A daemon that bridges the system extensions to the cloud server. Written in
Go with a C bridge for XPC communication.

```
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

The agent runs two parallel receiver loops (ESF + Network), each with
exponential backoff reconnection (1s initial, 30s max).

## Server components

### Ingest handler (`server/ingest/`)

Stateless HTTP endpoint at `POST /api/events`. Validates required fields
(`event_id`, `host_id`, `event_type`, `timestamp_ns`), enforces 10 MB request
limit, and inserts into the `events` table with `INSERT IGNORE` for
idempotent deduplication.

A standalone `fleet-edr-ingest` binary (`server/cmd/fleet-edr-ingest/`) can
run the ingest handler independently for horizontal scaling.

### Processor (`server/processor/`)

Polls the `events` table for unprocessed rows every 500ms. For each batch:

1. **Graph builder** (`server/graph/builder.go`) materializes process state:
   - `fork` -> creates process record
   - `exec` -> updates path, args, uid, gid, code signing, SHA-256
   - `exit` -> sets exit time and code
   - Handles PID reuse, exec-without-fork, fork-without-exec

2. **Detection engine** (`server/detection/engine.go`) evaluates rules:
   - Iterates registered rules against the event batch
   - Persists findings as alerts with event linkage
   - Returns errors on alert persistence failures (batch is retried)

3. Marks events as processed (or unclaims on failure for retry)

### Detection rules (`server/detection/rules/`)

Rules implement the `detection.Rule` interface:

```go
type Rule interface {
    ID() string
    Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]Finding, error)
}
```

Current rules:
- **suspicious_exec** -- detects when a non-shell process spawns a shell and
  either (a) a child executes from a suspicious path (`/tmp/`, `/var/tmp/`,
  `/private/tmp/`, `/dev/shm/`, or path traversal), or (b) the shell or its
  children make an outbound network connection within 30 seconds.

### Store (`server/store/`)

MySQL 8.4 persistence layer. Five tables:

| Table | Purpose |
|-------|---------|
| `events` | Raw event storage with processed flag for claim/process/mark cycle |
| `processes` | Materialized process state (PID, path, args, fork/exec/exit times) |
| `alerts` | Detection findings with deduplication (host_id, rule_id, process_id) |
| `alert_events` | Links alerts to triggering events |
| `commands` | Server-to-agent commands (kill_process) with status lifecycle |

### REST API (`server/api/`)

Read endpoints for the UI:

| Endpoint | Returns |
|----------|---------|
| `GET /api/hosts` | Host list with event counts and last-seen |
| `GET /api/hosts/{id}/tree` | Process forest with children, network events |
| `GET /api/hosts/{id}/processes/{pid}` | Process detail with network + DNS |
| `GET /api/alerts` | Filterable alert list |
| `GET /api/alerts/{id}` | Single alert with linked event IDs |
| `PUT /api/alerts/{id}` | Update alert status |
| `GET /api/commands` | Agent command polling |
| `POST /api/commands` | Create command (from UI) |
| `PUT /api/commands/{id}` | Agent reports command result |
| `GET /health` | Health check |

### Web UI (`ui/`)

React 19 + TypeScript + Vite + D3.js. Embedded in the Go server binary via
`//go:embed`. Served at `/ui/`.

Pages:
- **Login** -- API key entry (stored in sessionStorage)
- **Host list** -- table of enrolled hosts with event counts
- **Process tree** -- D3 hierarchical tree with click-to-select, alert badges
- **Process detail** -- side panel with metadata, network connections, DNS
  queries, kill button, alert status management
- **Alert list** -- filterable table with severity badges, status transitions

## Data flow

```
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

Events are immutable once ingested. The processor reads unprocessed events,
materializes process state, runs detection, and marks them done. This
decoupling means the ingest path has no dependencies on processing speed.

## Code signing and XPC trust model

All on-device binaries are signed with the Victor Lyuboslavsky personal
Developer ID team certificate (team ID `FDG8Q7N4CC`). The system extension XPC servers validate
connecting peers via `xpc_connection_set_peer_code_signing_requirement`,
requiring `anchor apple generic and certificate leaf[subject.OU] = "FDG8Q7N4CC"`.

The agent binary must be signed with `--options runtime` (hardened runtime) for
XPC peer validation to work at the kernel level.

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

# Build and run the server (port 3316 for MySQL)
cd ui && npm run build && cd ..
go run ./server/cmd/fleet-edr-server/ -dsn "root@tcp(127.0.0.1:3316)/edr?parseTime=true"

# Open http://localhost:8088/ui/

# Run tests
EDR_TEST_DSN="root@tcp(127.0.0.1:3316)/edr_test?parseTime=true" go test ./server/...
go test ./agent/... ./internal/...
```

### VM testing

For testing with real system extensions, use a macOS VM with SIP disabled
and developer mode on. See `docs/lessons-and-gotchas.md` for VM-specific
setup notes. The host app must be in `/Applications/` and signed with the
Fleet org certificate.
