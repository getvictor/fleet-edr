# Fleet EDR

A macOS Endpoint Detection and Response (EDR) system. It provides
real-time process monitoring, network attribution, behavioral detection, and response capabilities.

## Architecture

### On-device

- **System extension** (Swift) -- subscribes to macOS Endpoint Security Framework events
  (exec, fork, exit, open) and captures process metadata, code signing info, and file hashes
- **Network extension** (Swift) -- monitors TCP/UDP connections via NEFilterDataProvider with
  process attribution
- **Agent daemon** (Go) -- receives events from extensions over XPC, queues them in SQLite,
  and uploads to the server

### Server

- **Ingestion API** -- accepts event batches from agents over HTTP
- **Processor** -- materializes a per-host process graph from raw events and runs detection rules
- **Detection engine** -- evaluates behavioral rules against materialized process trees
- **MySQL storage** -- events, processes, alerts, and commands
- **Web UI** (React/TypeScript) -- process tree visualization, alert management, and response actions

## Components

```
extension/edr/       Swift system extension + network extension (Xcode project)
agent/               Go agent daemon (XPC receiver, SQLite queue, uploader)
server/              Go server (ingestion, processor, detection, REST API)
ui/                  React/TypeScript frontend (Vite, D3.js process tree)
```

## Quick start

```bash
# Start MySQL
docker compose up mysql -d

# Run the server
cd server && go run ./cmd/fleet-edr-server/ -dsn "root@tcp(127.0.0.1:3306)/edr?parseTime=true"

# Build the UI (embedded in the server binary)
cd ui && npm run build

# Open http://localhost:8088/ui/
```

## Running tests

```bash
# Server (requires MySQL)
cd server && go test ./...

# Agent
cd agent && go test ./...

# UI lint
cd ui && npx eslint .
```
