# Deploy the EDR server on Render

This is the fastest way to stand up a Fleet EDR server for an evaluation or pilot: Render hosts the server and a bundled MySQL, and terminates TLS at its edge so there are no certificates to manage. Once the server is up, deploy the agent to your Macs through your MDM (see [fleet-deployment.md](fleet-deployment.md) for the Fleet recipe, or [mdm-deployment.md](mdm-deployment.md) for the vendor-neutral contract).

For a self-hosted server with your own TLS certificates instead, see the production docker-compose stack (`docker-compose.prod.yml`).

## What the blueprint creates

The [`render.yaml`](../render.yaml) blueprint provisions two services:

- **`fleet-edr-server`** (web): the `ghcr.io/getvictor/fleet-edr-server` image behind Render's TLS-terminating edge. It listens plaintext HTTP inside Render's network (`EDR_TLS_TERMINATED_BY_PROXY=1`) while agents reach it over Render's publicly-trusted `https://…onrender.com` URL, so the data plane is encrypted end to edge with zero certificate management. Schema migrations apply automatically on boot.
- **`fleet-edr-mysql`** (private service): a MySQL 8.4 instance (the official image, matching the version the rest of the stack builds and tests against) with a 10 GB disk, reachable only from the server. Good for pilots; swap to a managed database later by setting `EDR_DSN` on the server and removing this service.

No Redis is needed: the server is stateless (ADR-0010) and keeps all durable state in MySQL.

## Deploy

1. Click the button (or in the Render dashboard: **New > Blueprint**, point it at this repo):

   [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/getvictor/fleet-edr)

2. Render reads `render.yaml`, creates both services, generates the MySQL password and the agent enroll secret, and wires them together. First boot runs the migrations and seeds a break-glass admin.

3. When the server is live, open its Render URL. The admin UI is at `https://<your-service>.onrender.com/ui/`.

## After it is up

- **Enable break-glass sign-in for your Render URL.** Break-glass uses WebAuthn, which binds credentials to a specific host, so on a non-localhost deployment you must tell the server its public host. Once Render assigns the URL, set two env vars on the `fleet-edr-server` service and let it redeploy: `EDR_BREAKGLASS_RP_ID=<your-service>.onrender.com` and `EDR_BREAKGLASS_RP_ORIGINS=https://<your-service>.onrender.com`. Without them the break-glass ceremony fails.
- **Redeem the break-glass admin.** On first boot the server prints a one-time break-glass redemption URL (not a password) to its logs. In the Render dashboard open the `fleet-edr-server` service logs and search for the break-glass banner, open the URL, and register a passkey to become admin. Then configure OIDC for ongoing access: set `EDR_OIDC_ISSUER`, `EDR_OIDC_CLIENT_ID`, `EDR_OIDC_CLIENT_SECRET`, and `EDR_OIDC_REDIRECT_URL` together (the server rejects a partial OIDC config), and remove `EDR_AUTH_ALLOW_NO_OIDC`; see [okta-setup.md](okta-setup.md) for the IdP-side steps.
- **Grab the enroll secret.** In the `fleet-edr-server` service, **Environment** tab, copy the generated `EDR_ENROLL_SECRET`. Your MDM install script needs it (it is the `EDR_ENROLL_SECRET` in [fleet-deployment.md](fleet-deployment.md)'s install script).
- **Note your server URL.** `https://<your-service>.onrender.com` is the `EDR_SERVER_URL` agents enroll against. Set it as the `FLEET_SECRET_EDR_SERVER_URL` (or equivalent) in your MDM.

## Deploy the agents

With the server URL and enroll secret in hand, follow [fleet-deployment.md](fleet-deployment.md) to push the agent `.pkg`, the two `.mobileconfig` profiles, and the install script through Fleet (or your MDM of choice). The agents enroll directly to the Render URL; Fleet never sees the EDR data plane.

## Notes and limits

- **Custom domain:** add one in Render's dashboard; the agents then enroll against your domain instead of the `onrender.com` URL. Render manages the certificate either way.
- **The bundled MySQL is pilot-grade.** It persists on a Render disk but has no managed backups. For production, point `EDR_DSN` at a managed MySQL and drop the bundled service.
- **Do not set `EDR_TLS_CERT_FILE`/`EDR_TLS_KEY_FILE` alongside `EDR_TLS_TERMINATED_BY_PROXY=1`.** The server rejects that combination: terminate TLS at the proxy (the Render default here) or at the server (self-hosted), never both.
