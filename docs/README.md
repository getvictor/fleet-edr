# Fleet EDR documentation

Operator-facing documentation for Fleet EDR. For developer setup see the
repo-root `README.md`.

## Who reads what

| You are | Start here |
|---|---|
| Standing up the server for the first time | [`install-server.md`](install-server.md) |
| Evaluating the agent on a handful of Macs without MDM | [`install-agent-manual.md`](install-agent-manual.md) |
| Deploying to a fleet via any MDM (Jamf, Kandji, Intune, mosyle, Fleet) | [`mdm-deployment.md`](mdm-deployment.md) |
| Deploying specifically via Fleet MDM | [`fleet-deployment.md`](fleet-deployment.md) |
| Upgrading, rotating secrets, recovering from a wiped server, reading logs | [`operations.md`](operations.md) |
| Integrating with the server's HTTP API | [`api.md`](api.md) |
| Understanding how the pieces fit together | [`architecture.md`](architecture.md) |

## Shape of a Fleet EDR deployment

- **Server**: container image `ghcr.io/getvictor/fleet-edr-server` running
  behind your TLS-terminating ingress, backed by MySQL 8.4. Serves the
  agent ingestion API, the admin web UI, and the OTel metric pipeline.
- **Agent**: signed + notarized `.pkg` installed on each macOS endpoint.
  Runs as a LaunchDaemon, receives events from an embedded system
  extension over XPC, queues them in SQLite, uploads to the server.
- **MDM profiles**: two signed `.mobileconfig` files that pre-approve the
  system extension and grant Full Disk Access. Delivered by whichever
  MDM the customer uses.
- **Install script**: a one-line Bash snippet your MDM runs before the
  `.pkg` installer to drop the enroll secret into `/etc/fleet-edr.conf`.

Artifacts ship on each [GitHub Release](https://github.com/getvictor/fleet-edr/releases):

- `fleet-edr-<version>.pkg` (signed + notarized)
- `edr-system-extension.mobileconfig` (signed)
- `edr-tcc-fda.mobileconfig` (signed)
- `SHA256SUMS` (verify your downloads)

Server image is tagged on each release: `ghcr.io/getvictor/fleet-edr-server:<version>`.
`:latest` only advances on stable (non-`-rc`, non-`-beta`) tags.

## Support

- Issues: https://github.com/getvictor/fleet-edr/issues
- Security reports: follow the SECURITY.md process at the repo root.
