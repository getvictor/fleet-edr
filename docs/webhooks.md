# Outbound alert webhooks

Fleet EDR can POST every alert to an HTTP endpoint you control, so alerts reach your team (Slack, PagerDuty, a SIEM, a SOAR runbook, or your own glue) in seconds instead of waiting for someone to open the console. This page covers configuring destinations, the payload shape, and how a receiver verifies a delivery. Operators manage destinations under Admin, Settings, Webhooks in the console, backed by the API described here.

Related: deferred hardening and vendor-specific formatters are tracked in [issue #565](https://github.com/getvictor/fleet-edr/issues/565). Feature proposal: [issue #496](https://github.com/getvictor/fleet-edr/issues/496).

## What gets delivered

A delivery fires when an alert is created, and (for destinations subscribed to it) when an alert's status changes. Delivery is durable: the delivery is queued in the same database transaction that persists the alert, so it survives a server restart and is never queued if the alert itself did not persist. Delivery is at-least-once, so a receiver must deduplicate on the delivery id (see below).

## Configuring destinations

Destination management requires the `webhook.manage` permission (granted to the admin role). The console page and the operator API both sit under the session cookie plus CSRF boundary. A destination has:

| Field          | Meaning                                                                                    |
| -------------- | ------------------------------------------------------------------------------------------ |
| `name`         | A label for the destination.                                                               |
| `url`          | The receiver endpoint. Must be `https`. Blocked address ranges are refused (see security). |
| `secret`       | The signing secret. Write-only: sealed at rest and never returned by any read.             |
| `event_types`  | Which events to deliver: `alert.created`, `alert.status_changed`, or both.                 |
| `min_severity` | Minimum alert severity to deliver: `low`, `medium`, `high`, or `critical`.                 |
| `enabled`      | Whether the destination receives deliveries.                                               |

The signing secret is required on create. On update, an empty secret keeps the stored one so you can edit other fields without re-entering it. A deployment must be started with a root secret (`EDR_SECRET_KEY`) for destinations to be creatable; without one the API returns `503 webhook_not_configured`.

### API

| Method + path                                | Purpose                                                        |
| -------------------------------------------- | -------------------------------------------------------------- |
| `GET /api/settings/webhooks`                 | List destinations (never includes the secret).                 |
| `POST /api/settings/webhooks`                | Create a destination.                                          |
| `PUT /api/settings/webhooks/{id}`            | Update a destination.                                          |
| `DELETE /api/settings/webhooks/{id}`         | Delete a destination and its queued deliveries.                |
| `GET /api/settings/webhooks/{id}/deliveries` | Recent delivery outcomes for the destination (status readout). |
| `POST /api/settings/webhooks/{id}/test`      | Send a signed test delivery and report the outcome.            |

The console exposes a **Send test** action per destination (backed by the test endpoint): it signs and POSTs a synthetic `webhook.test` payload through the same egress guards as a real delivery and shows the immediate result, so you can confirm a destination works before relying on it. It creates no alert.

## Payload

Each request body is a versioned JSON envelope. Example of an `alert.created` delivery:

```json
{
  "schema_version": "1.0",
  "event_id": "9f1c2e3a-...",
  "event_type": "alert.created",
  "occurred_at": "2026-07-01T18:22:03.481Z",
  "delivery_attempt": 1,
  "alert": {
    "id": 48213,
    "status": "open",
    "severity": "high",
    "source": "detection",
    "title": "Credential access via LSASS",
    "description": "...",
    "rule_id": "cred_access_lsass",
    "techniques": ["T1003.001"],
    "created_at": "2026-07-01T18:22:03.400Z",
    "updated_at": "2026-07-01T18:22:03.400Z"
  },
  "host": { "id": "..." },
  "process": { "pid": 1234 },
  "links": { "console": "https://<external-url>/ui/alerts?id=48213" }
}
```

An `alert.status_changed` delivery additionally carries `alert.previous_status`. The payload never contains any signing secret. `event_id` is stable across retries of the same delivery; deduplicate on it.

## Verifying a delivery

Requests are signed with the [Standard Webhooks](https://www.standardwebhooks.com/) scheme, so off-the-shelf verifier libraries work. Three headers are sent:

| Header              | Value                                                   |
| ------------------- | ------------------------------------------------------- |
| `Webhook-Id`        | The delivery id (also the `event_id` in the body).      |
| `Webhook-Timestamp` | Unix seconds when the request was signed.               |
| `Webhook-Signature` | `v1,<base64>` where the MAC is over the signed content. |

The signed content is the id, the timestamp, and the raw body joined by a full stop:

```text
signed = "{Webhook-Id}.{Webhook-Timestamp}.{raw-body}"
signature = "v1," + base64(HMAC_SHA256(secret, signed))
```

A receiver should: recompute the signature with the shared secret and compare in constant time; reject a `Webhook-Timestamp` outside a tolerance window (5 minutes is typical) to defend against replay; and deduplicate on `Webhook-Id` because delivery is at-least-once.

## Delivery reliability

A delivery is attempted until the receiver returns a 2xx or a bounded retry cap is reached, with exponential backoff between attempts. A delivery that exhausts its retries is marked failed and surfaced in the delivery-status readout rather than dropped. Return a 2xx quickly and process asynchronously; a slow receiver is bounded by the sender's per-request timeout.

## Security

- Destination URLs must use `https`.
- Outbound requests are guarded against SSRF: the server refuses to connect to loopback, private (RFC 1918), carrier-grade NAT (RFC 6598), link-local (including the cloud instance-metadata address), and unique-local addresses, evaluated against the address resolved at delivery time, and does not follow redirects.
- Signing secrets are sealed at rest and never returned over the API.
