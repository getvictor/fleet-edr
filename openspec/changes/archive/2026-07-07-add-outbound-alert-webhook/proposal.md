## Why

Alerts today only leave the system through the authenticated console and REST API (`GET /api/alerts`, `server/detection/internal/operator/handler.go`). An alert is seen only if a human happens to be logged in looking at it, and no SOC staffs someone to watch a single product's dashboard, so in practice new alerts reach nobody automatically. There is currently zero out-of-band delivery: no webhook, no email, no syslog or SIEM export, no config surface, and no delivery worker. This fails a table-stakes EDR evaluation criterion, "alerts reach your team in seconds," and it blocks the AI-triage direction where an external agent needs to be told that a new alert needs attention (issue #496).

The server is stateless and runs multiple replicas behind a load balancer (ADR-0010), so a fire-and-forget POST from the detection or request path is the wrong shape: a replica dying mid-delivery silently drops the alert. Delivery must be durable and must survive a replica restart.

This change ships a secure, enterprise-usable minimum: a generic HMAC-signed HTTP POST delivered through a transactional outbox, managed at runtime through the admin surface. It is deliberately not Slack-specific or SIEM-specific; it is the raw signed-POST primitive that a customer's own glue, a SOAR runbook, or a later vendor formatter all build on. Vendor payload transforms and additional hardening are tracked as unmilestoned follow-ups.

## What changes

- Add operator-managed webhook destinations stored in the database, each carrying a name, an https URL, an encrypted signing secret, an event-type and minimum-severity filter, and an enabled toggle. The configuration is managed at runtime through an admin surface (the same shape as SSO configuration, #375), not through static environment or file config. The signing secret is sealed at rest and is never returned by any read of a destination.
- On alert creation, and on an alert status change, durably queue one delivery for every enabled destination whose filter matches, in the same database transaction that persists the alert (or the status change). A queued delivery is therefore never lost if the process dies immediately after commit, and is never queued if the alert itself did not persist.
- A background delivery worker drains the queue and POSTs a signed, versioned JSON payload to each destination, retrying failed deliveries with exponential backoff up to a bounded attempt cap. Delivery is at-least-once; each delivery carries a stable event id that receivers dedup on.
- Sign every request with HMAC-SHA256 over the request id, timestamp, and body, following the Standard Webhooks header convention (`webhook-id`, `webhook-timestamp`, `webhook-signature`) so receivers can verify with off-the-shelf libraries. The timestamp is bound into the signature so receivers can reject replays.
- Guard outbound requests against SSRF: require https, refuse to deliver to (and refuse to follow a redirect to) a URL whose host resolves to a loopback, private, link-local (including the cloud instance-metadata address), or unique-local address, and bound each attempt with a request timeout and a maximum response size so a slow or hostile receiver cannot stall the delivery worker.
- Add a Webhooks page to the admin Settings area, beside Single sign-on, Users, and Service accounts, to create, edit, disable, delete, and test destinations and to show recent per-destination delivery outcomes. The page is gated on a new `webhook.manage` permission granted to the admin role.

Out of scope, tracked as unmilestoned follow-ups (parent #496): zero-downtime secret rotation with a dual-secret overlap window; circuit-breaker auto-disable of chronically failing destinations; an optional static bearer-token auth header per destination; DNS-rebinding connection pinning; mTLS to receivers; vendor payload formatters (Slack, Teams, PagerDuty); SIEM export formats (Splunk HEC, Syslog, CEF, LEEF); and an advanced per-destination subscription and routing UI.

## Capabilities

### Added capabilities

- `alert-webhook-delivery`: operator-managed webhook destinations with a sealed write-only secret; durable, atomic enqueue of a delivery per matching destination on alert creation and status change; a signed, versioned delivery payload; reliable at-least-once delivery with retries, backoff, bounded attempts, and multi-replica safety; SSRF-safe outbound egress; and a test-send plus delivery-status readout.

### Modified capabilities

- `web-ui`: add the Webhooks section to the admin settings area, gated on `webhook.manage`, with a write-only secret field and a delivery-health readout.
- `server-identity-authorization`: add the `webhook.manage` action and grant it to the admin role.

## Impact

- Code: a new detection migration `server/detection/migrations/00009_alert_webhook_delivery.sql` creating a destinations table and a delivery outbox table; an enqueue hook in the alert insert path (`server/detection/internal/mysql/alerts.go`) and the alert status-update path; a delivery worker under the detection pipeline, wired beside the existing background workers in `server/cmd/fleet-edr-server/main.go`; an admin handler for destination CRUD, test-send, and delivery status; a secret sealer reused from the SSO configuration pattern (factored into a shared package); and the React UI (`ui/src/permissions-core.ts`, `ui/src/api.ts`, `ui/src/components/Webhooks/`, `SettingsLayout.tsx`, `App.tsx`).
- Data: one additive migration creating `webhook_destination` and `webhook_delivery`. No backfill. Rollback drops the two tables; alert creation is unaffected because the enqueue is a no-op when no destination matches.
- Security: outbound requests to operator-supplied URLs introduce an SSRF surface, mitigated by the egress guards above; signing secrets are encrypted at rest and never returned over the API; the configuration surface is gated on `webhook.manage`.
- Observability: delivery attempts, successes, and failures are recorded through the existing OTel meter pipeline (no new Prometheus endpoint).
- APIs: new authed routes for destination CRUD, test-send, and delivery status under the operator session plus CSRF boundary. No change to the agent protocol, the event schema, or the persisted host token.
- Rollback is a code revert plus dropping the two tables. Deployments with no destination configured behave exactly as before.
