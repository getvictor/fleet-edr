# Fleet EDR documentation

Operator-facing documentation for Fleet EDR. For developer setup see the repo-root [`README.md`](../README.md).

## Who reads what

| You are                                                                   | Start here                                           |
| ------------------------------------------------------------------------- | ---------------------------------------------------- |
| Standing up the server for the first time                                 | [`install-server.md`](install-server.md)             |
| Evaluating the agent on a handful of Macs without MDM                     | [`install-agent-manual.md`](install-agent-manual.md) |
| Deploying to a fleet via any MDM (Jamf, Kandji, Intune, mosyle, Fleet)    | [`mdm-deployment.md`](mdm-deployment.md)             |
| Deploying specifically via Fleet MDM                                      | [`fleet-deployment.md`](fleet-deployment.md)         |
| Upgrading, rotating secrets, recovering from a wiped server, reading logs | [`operations.md`](operations.md)                     |
| Integrating with the server's HTTP API                                    | [`api.md`](api.md)                                   |
| Understanding how the pieces fit together                                 | [`architecture.md`](architecture.md)                 |
| Setting up Okta or another OIDC IdP for operator login                    | [`okta-setup.md`](okta-setup.md)                     |
| Recovering when SSO is unavailable, registering a second security key     | [`breakglass.md`](breakglass.md)                     |
| Reviewing what threats v0.1 covers and where the gaps are                 | [`threat-model.md`](threat-model.md)                 |

## Getting started

The fastest path to an evaluation: deploy the server on Render (one click, TLS and MySQL handled for you), then push the agent to your Macs through Fleet MDM. See [deploy-render.md](deploy-render.md) for the server and [fleet-deployment.md](fleet-deployment.md) for the agents.

## Shape of a Fleet EDR deployment

- **Server**: container image `ghcr.io/getvictor/fleet-edr-server` running behind your TLS-terminating ingress (or [Render](deploy-render.md), which provides the ingress), backed by MySQL 8.4. Serves the agent ingestion API, the admin web UI, and the OTel metric pipeline.
- **Agent**: signed + notarized `.pkg` installed on each macOS endpoint. Runs as a LaunchDaemon, receives events from an embedded system extension over XPC, queues them in SQLite, uploads to the server.
- **MDM profiles**: two unsigned `.mobileconfig` files that pre-approve the system extension and grant Full Disk Access. Delivered by whichever MDM the customer uses; the MDM signs them at delivery time.
- **Install script**: a one-line Bash snippet your MDM runs before the `.pkg` installer to drop the enroll secret into `/etc/fleet-edr.conf`.

Artifacts ship on each [GitHub Release](https://github.com/getvictor/fleet-edr/releases):

- `fleet-edr-<version>.pkg` (signed + notarized)
- `edr-system-extension.mobileconfig` (unsigned; your MDM signs at delivery)
- `edr-tcc-fda.mobileconfig` (unsigned; your MDM signs at delivery)
- `SHA256SUMS` (verify your downloads)

Server image is tagged on each release: `ghcr.io/getvictor/fleet-edr-server:<version>`. `:latest` only advances on stable (non-`-rc`, non-`-beta`) tags.

## Support

- Issues: https://github.com/getvictor/fleet-edr/issues
- Security reports: follow the SECURITY.md process at the repo root.
