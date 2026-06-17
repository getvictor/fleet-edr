# Fleet EDR

<!-- License & release -->

[![License: MIT](https://img.shields.io/github/license/getvictor/fleet-edr?style=flat-square)](LICENSE) [![Release](https://img.shields.io/github/v/release/getvictor/fleet-edr?include_prereleases&style=flat-square)](https://github.com/getvictor/fleet-edr/releases)

<!-- Build & quality -->

![Go version](https://img.shields.io/github/go-mod/go-version/getvictor/fleet-edr?filename=go.mod&style=flat-square) [![Tests](https://github.com/getvictor/fleet-edr/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/getvictor/fleet-edr/actions/workflows/test.yml) [![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=getvictor_fleet-edr&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=getvictor_fleet-edr) [![Coverage](https://img.shields.io/codecov/c/github/getvictor/fleet-edr?style=flat-square&logo=codecov)](https://codecov.io/gh/getvictor/fleet-edr)

<!-- Security scanners -->

[![CodeQL](https://github.com/getvictor/fleet-edr/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/getvictor/fleet-edr/actions/workflows/codeql.yml) [![govulncheck](https://github.com/getvictor/fleet-edr/actions/workflows/go-vulncheck.yml/badge.svg?branch=main)](https://github.com/getvictor/fleet-edr/actions/workflows/go-vulncheck.yml) [![OSV-Scanner](https://github.com/getvictor/fleet-edr/actions/workflows/osv-scanner.yml/badge.svg?branch=main)](https://github.com/getvictor/fleet-edr/actions/workflows/osv-scanner.yml)

<!-- Supply chain -->

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12994/badge)](https://www.bestpractices.dev/projects/12994) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/getvictor/fleet-edr/badge)](https://scorecard.dev/viewer/?uri=github.com/getvictor/fleet-edr) [![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev/spec/v1.0/levels#build-l2) [![cosign keyless](https://img.shields.io/badge/cosign-keyless-9cf?style=flat-square&logo=sigstore)](docs/best-practices.md#4-supply-chain-security)

Fleet EDR is an open-source endpoint detection and response (EDR) system for macOS fleets. It gives security teams real-time visibility into process, network, and DNS activity on Apple Silicon Macs, runs behavioral detection rules against a materialized process graph, and can block execution or kill a process on the endpoint. It is fully self-hosted: your own server, your own data, no SaaS dependency.

<p align="center">
  <a href="https://www.youtube.com/watch?v=3pPhDc-AIOQ">
    <img src="https://img.youtube.com/vi/3pPhDc-AIOQ/maxresdefault.jpg" alt="Fleet EDR demo video" width="640">
  </a>
  <br />
  <a href="https://www.youtube.com/watch?v=3pPhDc-AIOQ"><strong>▶ Watch the demo</strong></a>
</p>

## Get started

Either deploy it and enroll real Macs, or try it first with the Mac-free demo.

### Deploy it

Two steps. Stand up a server, then push the agent to your Macs.

**1. Stand up the server.**

- **One-click on Render (fastest).** The blueprint provisions the server and a MySQL database behind Render's TLS edge, so there are no certificates to manage. Full walkthrough: [docs/deploy-render.md](docs/deploy-render.md).

  [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/getvictor/fleet-edr)

- **Or self-host the container** on any container host (Docker, Kubernetes, AWS ECS/EKS, GCP, Azure, or your own VM). The server is a standard multi-arch Linux image. Setup, secrets, and TLS: [docs/install-server.md](docs/install-server.md).

**2. Deploy the agent to your Macs** (Apple Silicon, macOS 26+). The agent ships as a Developer ID-signed, notarized `.pkg` plus two `.mobileconfig` profiles, delivered by your MDM.

- **Via MDM** (Fleet, Jamf, Kandji, Intune, mosyle): the vendor-neutral contract is in [docs/mdm-deployment.md](docs/mdm-deployment.md); the Fleet-specific recipe is in [docs/fleet-deployment.md](docs/fleet-deployment.md).
- **Manually on 1 to 5 Macs** (no MDM, for evaluation): [docs/install-agent-manual.md](docs/install-agent-manual.md).

Once agents enroll, open the server's `/ui/` to watch hosts, process trees, and alerts in real time.

### Try the demo (no Mac required)

Want to look before deploying? Evaluate the full server, UI, and detection pipeline in about five minutes. No Apple Silicon Mac, MDM, or Apple entitlement needed.

```sh
docker compose -f docker-compose.demo.yml up
```

Open <https://localhost:8088/ui/>, accept the self-signed certificate warning, and sign in with the bundled SSO account `demo@fleet-edr.local` / `demo`.

You'll see two real macOS hosts (an engineer laptop and a CI build server), each with a deep process graph and correlated network and DNS activity drawn from genuine scrubbed captures. Woven into that ambient activity are five fired ATT&CK detections: a credential keychain dump and a DNS C2 beacon (exec, DNS, and outbound connection correlated across all three streams), plus sudoers tampering, launchd persistence, and an application-control block. Every alert comes from the real ingestion and detection pipeline, not hand-inserted rows, and the benign activity raises no false alarms.

Notes:

- The on-device half (system extension, network extension, agent) needs an Apple-granted Endpoint Security entitlement and Apple Silicon, so it cannot run in Docker. The demo exercises the server, UI, and detection pipeline; deploy on a real Mac (above) to see live capture.
- Response actions enqueue but never complete in the demo because no live agent is connected.
- Evaluation only: empty MySQL password, self-signed cert, checked-in dev secrets. Do not expose it to the internet.
- To build the demo images from source instead of pulling the release tag: `docker compose -f docker-compose.demo.yml -f docker-compose.demo.build.yml up --build`.

## What it does

- **Real-time macOS monitoring.** On-device extensions capture process execution, fork/exit, file access, DNS queries, and network connections, streamed continuously to your server.
- **Process-graph correlation.** The server reconstructs a live per-host process tree, so every alert carries the full ancestry that led to it.
- **Behavioral detections.** A catalog of rules covering credential access, persistence, privilege escalation, process injection, command-and-control beaconing, and suspicious execution, including detections that correlate exec, DNS, and network together.
- **Application control.** Block execution by binary hash, path, CDHash, signing ID, team ID, or leaf certificate, enforced on the endpoint at exec time.
- **Response.** Kill a running process on a host on demand.
- **Operator UI with RBAC, SSO, and an append-only audit log.** OIDC single sign-on plus a WebAuthn break-glass path, five built-in roles, and an immutable record of every privileged action.

For the full per-release capability list, see the [changelog](CHANGELOG.md).

## How it works

### On-device

- **System extension** (Swift): subscribes to macOS Endpoint Security Framework events (exec, fork, exit, open) and captures process metadata, code-signing info, and file hashes.
- **Network extension** (Swift): monitors TCP/UDP connections with process attribution, and resolves DNS to emit per-process `dns_query` events.
- **Agent daemon** (Go): receives events from the extensions over XPC, buffers them in a durable SQLite queue, and uploads to the server (store-and-forward, so a transient outage doesn't lose events).

### Server

- **Ingestion API**: accepts event batches from agents over HTTP.
- **Processor**: materializes a per-host process graph from raw events and runs the detection rules.
- **MySQL storage**: events, processes, alerts, and commands. The server is stateless (ADR-0010), so it scales as multiple replicas behind a load balancer.
- **Web UI** (React/TypeScript): process-tree visualization, alert management, and response actions.

## Documentation

Operator and reference docs live in [`docs/`](docs/):

| Topic                                                    | Doc                                                                   |
| -------------------------------------------------------- | --------------------------------------------------------------------- |
| Deploy the server on Render                              | [`deploy-render.md`](docs/deploy-render.md)                           |
| Self-host the server stack                               | [`install-server.md`](docs/install-server.md)                         |
| Deploy the agent via any MDM                             | [`mdm-deployment.md`](docs/mdm-deployment.md)                         |
| Fleet MDM recipe                                         | [`fleet-deployment.md`](docs/fleet-deployment.md)                     |
| Evaluate on 1 to 5 Macs without an MDM                   | [`install-agent-manual.md`](docs/install-agent-manual.md)             |
| Day-2 ops: upgrades, rotations, backups, troubleshooting | [`operations.md`](docs/operations.md)                                 |
| Detection rules: behavior, ATT&CK mapping, configuration | [`detection-rules.md`](docs/detection-rules.md)                       |
| HTTP API reference                                       | [`api.md`](docs/api.md) + [`api/openapi.yaml`](docs/api/openapi.yaml) |
| Architecture decisions (the "why")                       | [`adr/`](docs/adr/)                                                   |

Repository layout:

```text
extension/edr/       Swift system extension + network extension (Xcode project)
agent/               Go agent daemon (XPC receiver, SQLite queue, uploader)
server/              Go server (ingestion, processor, detection, REST API)
internal/            Shared packages (envparse, etc.)
ui/                  React/TypeScript frontend (Vite, D3.js process tree)
docs/                Operator + reference docs, ADRs
```

## Development

Building from source or contributing? See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full guide. The short version:

```bash
mise install        # install pinned tools (Go, Node, golangci-lint, lefthook, task) from .tool-versions
lefthook install    # format + lint on commit, build + tsc on push
task lint:install   # builds the custom golangci-lint (with the commentwrap plugin)

task db:up          # local MySQL on 33306 (dev) / 33307 (test)
task build:ui       # build the UI, embedded into the server binary
task dev:server     # run the server at https://localhost:8088/ui/ (break-glass-only auth)

task test           # everything (Go + UI); requires MySQL
task --list         # the Taskfile is the source of truth for all commands
```

`task dev:server` runs break-glass-only. To exercise SSO locally against the bundled dex IdP, run `task qa:up` then `task dev:server:qa-oidc`; see [`docs/okta-setup.md`](docs/okta-setup.md) for a real OIDC tenant.

## License

[MIT](LICENSE)
