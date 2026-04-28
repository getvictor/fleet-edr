# HTTP API

Fleet EDR exposes a single HTTP API surface split across three audience
tiers:

- **Agents** on macOS endpoints post telemetry and poll for commands.
  They authenticate with a per-host bearer token.
- **Browsers** (the admin UI) authenticate with a session cookie + CSRF
  token. Everything the UI does is reachable as a JSON API from the
  same endpoints.
- **Operators / load balancers** hit `/livez`, `/readyz`, `/health`
  unauthenticated.

The machine-consumable spec is
[`api/openapi.yaml`](api/openapi.yaml). The OpenAPI 3.1 file is the
source of truth — this doc is the human overview.

Every running server also hosts a live browsable copy of the spec via
Redoc:

- `https://<your-server>/api/docs` — rendered docs page
- `https://<your-server>/api/openapi.yaml` — raw spec

Both endpoints are unauthenticated (the spec is already public on the
GitHub release page) and served from the same binary with no external
network calls.

Scheme depends on deployment — production runs behind TLS so both URLs
use `https://`; a dev instance started with `EDR_ALLOW_INSECURE_HTTP=1`
serves them over `http://`. Examples in this doc assume TLS.

## Base URL

```
https://<your-server>/
```

All endpoints are rooted at `/api/v1/` except the health probes and the
UI. There is no versioning header; when v2 lands it gets a parallel
`/api/v2/` tree.

## Content type

Request bodies are `application/json; charset=utf-8`. Response bodies,
when present, use the same type; several endpoints return `204 No
Content` with an empty body. Compressed request bodies are not
currently supported — do not set `Content-Encoding: gzip`.

## Auth models

### Host token (agents)

An agent POSTs `/api/v1/enroll` once with the shared enroll secret and
its hardware UUID. It receives an opaque `host_token`, stored in
`/var/db/fleet-edr/enrolled.plist`. Every subsequent request carries:

```
Authorization: Bearer <host_token>
```

Tokens are scoped to the host: agent A's token cannot read agent B's
commands or post events with `host_id=B`. Revoking an enrollment via
the admin UI invalidates the token immediately.

Endpoints that require a host token:
- `POST /api/v1/events`
- `GET  /api/v1/commands` (returns only the authenticated host's queue)
- `PUT  /api/v1/commands/{id}` (only commands owned by the host)

### Session cookie + CSRF (browsers)

The admin UI posts `/api/v1/session` with email + password. The
response sets `edr_session` (HttpOnly, Secure, SameSite=Lax) and
returns a `csrf_token` the UI stores client-side. Subsequent unsafe
requests (`POST`, `PUT`, `DELETE`) carry:

```
Cookie: edr_session=<opaque>
X-CSRF-Token: <csrf_token>
```

GET requests only need the cookie. Logout is `DELETE /api/v1/session`.

Endpoints that require the session cookie:
- `GET /api/v1/hosts`, `/api/v1/hosts/{id}/tree`,
  `/api/v1/hosts/{id}/processes/{pid}`
- `GET /api/v1/alerts`, `/api/v1/alerts/{id}`; `PUT /api/v1/alerts/{id}`
- `GET /api/v1/commands/{id}`, `POST /api/v1/commands`
- `GET /api/v1/admin/enrollments`,
  `POST /api/v1/admin/enrollments/{host_id}/revoke`
- `GET /api/v1/admin/policy`, `PUT /api/v1/admin/policy`
- `GET /api/v1/admin/attack-coverage` -- ATT&CK Navigator layer JSON
  describing which techniques the registered rules cover.
- `GET /api/v1/admin/rules` -- per-rule documentation surfaced by the
  UI's `/ui/rules/<id>` page; same data feeds `docs/detection-rules.md`.

### No auth

- `GET /livez`
- `GET /readyz` (used by LBs; leaks nothing beyond version + DB status)
- `GET /health` (alias of `/readyz`)

## Rate limits

Two IP-scoped buckets guard the auth boundary:

| Endpoint | Knob | Default |
|---|---|---|
| `POST /api/v1/enroll` | `EDR_ENROLL_RATE_PER_MIN` | 30/min/IP |
| `POST /api/v1/session` | `EDR_LOGIN_RATE_PER_MIN` | 6/min/IP |

Over-limit requests return `429 Too Many Requests` with a
`Retry-After` header.

Ingestion (`POST /api/v1/events`), command polling, and UI read
endpoints are not rate limited. If you proxy thousands of agents
through a single IP (NAT), monitor `edr.enroll.attempts` in OTel
metrics to confirm you're not hitting the enroll cap.

## Errors

Error responses use the following shape consistently:

```json
{"error": "unauthorized"}
```

Status codes follow HTTP semantics:

- `400` — malformed request body, invalid query param, wrong enum value
- `401` — missing / invalid auth (host token or session cookie)
- `403` — auth present but the caller isn't allowed (revoked
  enrollment, event `host_id` doesn't match token, etc.)
- `404` — row not found OR row not visible to this caller (we don't
  leak existence)
- `409` — conflict (e.g., enrollment already revoked)
- `429` — rate limited
- `500` — server-side error. Expect a retry to succeed.
- `503` — `/readyz` returns this when the DB is unreachable

## Generating clients

The OpenAPI 3.1 spec is usable with any modern codegen. Examples:

```sh
# TypeScript (via openapi-typescript)
npx openapi-typescript docs/api/openapi.yaml -o src/edr-api.ts

# Go (via oapi-codegen)
oapi-codegen -package edrapi docs/api/openapi.yaml > edrapi/client.gen.go

# Python (via openapi-python-client)
openapi-python-client generate --path docs/api/openapi.yaml
```

## What's not in the API (yet)

- Webhook / SIEM push. The server doesn't POST alerts outward;
  integrators poll `GET /api/v1/alerts`. Outbound integrations ship in
  v1.1+.
- Multi-tenant routing. All endpoints operate on a single customer
  boundary per server instance.
- Bulk enrollment / import. Agents enroll one at a time on first boot.
- Query language for events. Process tree + host list is what the UI
  exposes today; a flexible event query API is on the roadmap.
