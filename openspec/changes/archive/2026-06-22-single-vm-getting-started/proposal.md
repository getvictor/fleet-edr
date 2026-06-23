# Single-VM getting-started with an operator-controlled edge

## Why

A pilot agent stopped delivering events to the Render-hosted server, logging `uploader upload failed ... server returned 403` in a loop and then quarantining events. Reproduction against production isolated the cause: Render's Cloudflare edge runs a content-inspecting WAF that flags the agent's telemetry as an attack and returns `403` before the request reaches the app. Two same-size, same-header POSTs to `/api/events` proved it: a benign body returned `401` from the origin (`x-render-origin-server: Render`), while a body full of shell, C2, and SQL-injection strings returned a `403` Cloudflare block page with no origin header. The server's ingest path emits only `200/400/413/500` (host-token auth returns `401`), so the app never produced the `403`. Enroll secret and token were ruled out: a freshly enrolled token is blocked just the same.

Agent telemetry legitimately carries attack signatures (captured command lines, file paths, malware and C2 indicators), so any content-inspecting edge will keep blocking it, and compression does not help because a real WAF decompresses first. The structural fix is to keep the authenticated machine-to-machine ingest path off any managed-PaaS edge the operator cannot configure. Render exposes no customer-configurable WAF on any plan. The EDR's own reference reverse proxy (Caddy / NGINX) has no WAF, so self-hosting behind an edge the operator controls is the durable answer.

This change makes the default getting-started a single VM the operator controls, and pins the two invariants the incident exposed so they cannot silently regress.

## What changes

- **The default getting-started is a single VM with the operator's own domain.** A new `docker-compose.quickstart.yml` (MySQL + server + Caddy) plus `bootstrap.sh` and `docs/quickstart-vm.md` stand the stack up with one command. Caddy obtains a Let's Encrypt certificate automatically and reverse-proxies to the server over the private Docker network as a plain proxy with no managed ruleset, so the operator manages zero certificates and no content-inspecting edge sits in the agent path. The server runs in the existing proxy-terminated TLS mode (`EDR_TLS_TERMINATED_BY_PROXY=1`, see the `server-availability` "TLS may be terminated by a front proxy" requirement, unchanged here).
- **`deploy-render.md` is demoted from the default getting-started** and carries a warning that Render's edge WAF blocks agent telemetry by default and cannot be disabled by the customer, with the two workarounds (a Render support ticket exempting the agent routes, or deploying where the edge is yours). The repo-root and `docs/` READMEs now point at the quickstart as the recommended path.
- **The content-neutrality of ingest is pinned as a requirement** (`server-event-ingestion`): the authenticated ingest path decides acceptance on structure alone (auth, JSON shape, event count, body size, host-id match, server health) and never on payload content, so it never returns a content-block `403`. This is the server-side truth that makes a `403` diagnosably an edge artifact.
- **The supported edge topology is pinned as a requirement** (`server-availability`): the default getting-started deployment fronts the server with a plain reverse proxy under the operator's control, so agent telemetry carrying attack signatures reaches the server; a managed edge that runs a WAF the operator cannot disable is supported only when the agent routes are exempted from inspection.
- **`EDR_SECRET_KEY` is added to `docker-compose.prod.yml` + its README** (a latent boot failure: the server requires the deployment root secret unconditionally and the prod stack omitted it). No server behavior change; this is a packaging fix shipped alongside the quickstart.

### Not in this change

- High-availability / multi-replica topology and a no-VM PaaS path. Out of scope for this pass; the quickstart targets a single customer with 10 to 500 endpoints.
- Upload bandwidth optimization (gzip/zstd, persistent connections, HTTP/2). Tracked separately as getvictor/fleet-edr#405; it is explicitly not the WAF fix and must not be conflated with it.
- Any change to the server's request handling. The ingest path already behaves as the new `server-event-ingestion` requirement states; the requirement formalizes an invariant rather than altering behavior.
