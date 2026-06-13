# Render deployment blueprint

## Why

The getting-started story for the EDR is "stand up a server, then deploy agents via MDM." The agent/MDM side is documented (fleet-deployment.md), but standing up the server still means running the prod docker-compose with bring-your-own TLS certs, which is too much friction for an evaluation. A one-click "Deploy to Render" blueprint (server + bundled MySQL behind Render's TLS edge) makes the server side as easy as the agent side, mirroring how Fleet ships a `render.yaml`.

The blocker was TLS: the server makes TLS mandatory (#140 removed the plaintext-HTTP mode), but Render terminates TLS at its edge and proxies plaintext HTTP to the service. Fleet solves the identical problem with `FLEET_SERVER_TLS=false` and documents TLS-terminated-by-proxy as a first-class, recommended pattern (ALB SSL offload); it is the industry-standard PaaS/load-balancer posture.

## What changes

- **Gated proxy-TLS mode.** A new `EDR_TLS_TERMINATED_BY_PROXY=1` opt-in lets the server listen plaintext HTTP when an operator asserts a TLS-terminating proxy is in front. Mandatory-TLS stays the default; setting the flag together with cert files is rejected as ambiguous. In proxy mode the server logs a startup warning that it serves plaintext and must not be exposed directly. Agents connect to the proxy's publicly-trusted cert, so the data plane is encrypted end-to-edge with no cert management.
- **DSN from discrete parts.** When `EDR_DSN` is unset, the server composes it from `EDR_MYSQL_ADDRESS` / `EDR_MYSQL_USERNAME` / `EDR_MYSQL_PASSWORD` / `EDR_MYSQL_DATABASE`. Render (like Fleet's blueprint) wires a bundled DB's host:port and generated password into discrete env vars via `fromService` and cannot interpolate them into one DSN string; an explicit `EDR_DSN` still wins.
- **`render.yaml` blueprint.** Web service (`ghcr.io/getvictor/fleet-edr-server:latest`, `healthCheckPath: /readyz`, proxy-TLS on, enroll secret generated, DSN parts wired from the MySQL pserv) plus a bundled MySQL private service with a 10GB disk. No Redis (stateless, ADR-0010); no preDeployCommand (migrations self-apply on boot under the advisory lock).
- **`docs/deploy-render.md`.** Deploy-to-Render walkthrough that hands off to fleet-deployment.md for agents, completing the "Render + Fleet MDM" getting-started path.

### Not in this change

- Production durability/backup guidance for the bundled MySQL beyond the mounted disk (the doc notes swapping to a managed DB via `EDR_DSN`).
- Other PaaS targets (Fly, Cloud Run); the proxy-TLS flag and DSN-parts make them straightforward later.
