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
internal/            Shared packages (envparse, etc.)
ui/                  React/TypeScript frontend (Vite, D3.js process tree)
docs/adr/            Architecture Decision Records -- the "why" behind non-obvious choices
```

## First-time setup

```bash
# 0. Install mise (one-time, global). Picks https://mise.jdx.dev/getting-started.html
#    as the canonical source; pick whichever line matches your platform.
curl https://mise.run | sh                 # any Unix
brew install mise                          # macOS with Homebrew

# Activate mise in your shell so pinned tools appear on PATH. Without this step
# `mise install` downloads tools but they don't show up in `which task` / `which
# lefthook` etc. Pick the right line for your shell and append to the rc file.
echo 'eval "$(mise activate zsh)"'  >> ~/.zshrc   # zsh
echo 'eval "$(mise activate bash)"' >> ~/.bashrc  # bash
# Then open a new terminal, or `exec $SHELL`, so the activation takes effect.

# 1. Install every pinned tool (Go, Node, golangci-lint, lefthook, task).
#    Reads .tool-versions; asdf works the same way if you prefer it over mise.
mise install

# 2. Install git hooks (format + lint on commit, build + tsc on push).
lefthook install

# 3. See every available task.
task --list
```

## Quick start

```bash
# Start MySQL (local dev + test on ports 3316/3317)
task db:up

# Build the UI (embedded in the server binary via server/ui/dist/)
task build:ui

# Run the server
task dev:server
# Then open http://localhost:8088/ui/
```

## Running tests

```bash
task test        # everything (Go + UI) -- requires MySQL
task test:go     # Go with race detector
task test:ui     # Vitest
task lint        # golangci-lint, eslint, swiftlint, actionlint
```

Prefer `task --list` over memorising commands; the Taskfile is the source of truth
for reproducible invocations.
