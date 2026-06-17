# Changelog

Notable changes to Fleet EDR, newest first. This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0).

## [Unreleased]

### Removed

- **Render deployment support.** The one-click Render blueprint (`render.yaml`) and its guide are removed. Render's managed edge runs a content-inspecting WAF that blocks agent telemetry by default and cannot be disabled by the customer, so events silently fail to upload. The supported getting-started path is the single-VM quickstart ([docs/quickstart-vm.md](docs/quickstart-vm.md)), where you control the edge.

## [0.2.1] (2026-06-16)

Patch release on top of 0.2.0. Fixes the Mac-free Docker demo (`docker-compose.demo.yml`) so it presents correctly to evaluators. No agent or server runtime behavior changes; the fixes are confined to the demo seeder.

### Fixed

- **Demo process view stays populated across restarts.** On a restart against the persisted demo volume the seeder now slides the seeded timestamps forward, so the host process graph still falls inside the UI's default one-hour window instead of aging out and rendering empty. The shift is scoped to the demo's own hosts.
- **Demo alerts show a realistic process chain.** Woven attack scenarios are now re-parented under the captured host's interactive shell session instead of rooting directly at launchd, so an alert's process tree shows the full ancestry (for example `sshd -> zsh -> /usr/bin/security`) the way a real detection would.

## [0.2.0] (2026-06-16)

Incremental release on top of 0.1.1. Highlights: release signing modernized to the cosign v3 Sigstore bundle format, a detection-pipeline stall fixed, and the macOS system extensions now show recognizable names during a manual install.

### Added

- **Recognizable system-extension names.** The Endpoint Security and Network extensions now appear in macOS System Settings (Login Items & Extensions, Full Disk Access) as "Fleet EDR Security Extension" and "Fleet EDR Network Extension" instead of the generic "extension" / "networkextension", so an operator doing a manual (non-MDM) install can tell which Full Disk Access entry belongs to Fleet EDR.
- **Process-graph retention pruning.** The server prunes the process table on the configured retention window, bounding storage growth on long-running deployments.

### Changed

- **Modernized release signing (cosign v3).** Release artifacts are now signed as a single Sigstore bundle (`<file>.sigstore.json`) per file, and the server and demo-seed container images store their signatures and SBOM attestations as OCI 1.1 referring artifacts. Verify a download with `cosign verify-blob --bundle <file>.sigstore.json --certificate-identity-regexp ... --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
- **Pinned MySQL to 8.4.9** in the reference deployment stack.
- Updated UI build dependencies (esbuild, Vite, `@vitejs/plugin-react`).

### Fixed

- **Detection-pipeline stall on out-of-range UID/GID.** The process `uid`/`gid` columns are now `INT UNSIGNED`, so the macOS `nobody` account and the `KAUTH_UID_NONE` sentinel no longer overflow on insert; a single unpersistable event is isolated rather than wedging the whole detection pipeline.
- **Session-expiry handling.** The web UI redirects cleanly when a session expires instead of rendering affordances that then fail with 403.
- **OpenTelemetry noise.** Trimmed spurious telemetry output and tightened span/log scoping.

### Security

- **Hardened host enrollment tokens.** Host tokens are now verified with a keyed HMAC derived from a root secret.

### Observability

- Emit a `deployment.environment` resource attribute and scope the bundled SigNoz dashboards to it; added a dashboard filter plus render and metrics tuning.

### Documentation

- Tightened the install-server, MDM, and manual-agent deployment guides; led the README with deployment; documented the supported-version policy.

## [0.1.1] (2026-06-13)

First stable release. The product ships as two components, released together for now: the **macOS agent** (Apple Silicon, macOS 26+) and the **server** (a Linux container that runs anywhere containers do, cloud or on-prem). Core capabilities:

- **Real-time macOS endpoint monitoring.** An Endpoint Security system extension and a network extension capture process execution, fork/exit, file access, DNS queries, network connections, and background-task (launch item) registration, streamed continuously to the server.
- **Live process-graph correlation.** The server reconstructs a per-host process tree, including parent/child lineage and re-exec chains, so every alert carries the full process ancestry that led to it.
- **Out-of-the-box detection rules.** A catalog of behavioral detections covering credential access (keychain dumping), persistence (launch agents and daemons), privilege escalation (sudoers and launchd tampering), process injection (DYLD insertion), command-and-control beaconing, and suspicious execution chains.
- **Cross-stream correlation.** Rules reason over execution, DNS, and network together, catching multi-step behavior a single-signal tool misses, such as a process that beacons to a suspicious domain and then connects out.
- **Application control.** Block execution on the endpoint by binary hash, path, CDHash, signing ID, team ID, or leaf certificate, enforced at exec time before the process runs.
- **Process response.** Kill a running process on a host on demand from the server.
- **Tunable allowlists.** Per-rule allowlists suppress known-good management tooling, such as MDM agents that drop launch daemons or write sudoers, so legitimate activity does not generate noise.
- **Operator web UI.** Browse hosts, drill into process trees, triage and comment on alerts, and manage application-control policy.
- **SSO and break-glass authentication.** OIDC single sign-on with just-in-time user provisioning, plus a WebAuthn passkey break-glass path for recovery when SSO is unavailable.
- **Role-based access control.** Five built-in roles (super admin, admin, senior analyst, analyst, auditor) enforced through a single authorization chokepoint that no privileged action can bypass.
- **Append-only audit log.** Every privileged action and authorization decision is recorded immutably for later review.
- **Offline-tolerant agent.** A durable on-device SQLite queue buffers events when the server is unreachable and uploads them on reconnect, so nothing is lost during an outage.
- **Built to scale.** A stateless server runs as multiple replicas behind a load balancer, drains gracefully on deploy, applies schema migrations automatically, and enforces configurable event retention.
- **Flexible deployment.** The server is a standard Linux container image, so it runs on any container host (a Docker VM, Kubernetes, AWS ECS/EKS, GCP, Azure, or on-prem), with a one-click Render blueprint for the fastest start. Agents reach Macs through any MDM (Fleet, Jamf, Kandji, Intune, mosyle).
- **Supply-chain-hardened releases.** Every release ships a Developer ID-signed, Apple-notarized package alongside SBOMs, cosign signatures, and build provenance attestations.

[Unreleased]: https://github.com/getvictor/fleet-edr/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/getvictor/fleet-edr/releases/tag/v0.2.1
[0.2.0]: https://github.com/getvictor/fleet-edr/releases/tag/v0.2.0
[0.1.1]: https://github.com/getvictor/fleet-edr/releases/tag/v0.1.1
