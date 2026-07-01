## 1. Schema

- [x] 1.1 Add migration `server/detection/migrations/00009_alert_webhook_delivery.sql` with `+goose Up`/`+goose Down`:
  - `webhook_destination` (id, name, url, secret_sealed VARBINARY, event_types, min_severity, enabled, created_at, updated_at)
  - `webhook_delivery` outbox (id, alert_id, event_type, destination_id, payload, attempt, status ENUM('pending','delivered','failed'), next_attempt_at, last_status_code, last_error, created_at, updated_at), unique key on (alert_id, event_type, destination_id), index on (status, next_attempt_at)
- [x] 1.2 Down migration drops both tables

## 2. Sealed secret (shared)

- [x] 2.1 Factor the AES-256-GCM sealer out of `server/identity/internal/ssoconfig/crypto.go` into a shared package under `internal/` and repoint ssoconfig at it (find-prior-art: do not clone)
- [x] 2.2 Derive the webhook signing-secret key from the deployment root secret via the keyring under a distinct label; unit test seal/open round-trip and key-length invariant

## 3. Destination store + admin surface

- [x] 3.1 Detection store: CRUD for `webhook_destination`; the secret is accepted only on create/update, sealed before write, and never selected back into the read model
- [x] 3.2 Add the `webhook.manage` action to the identity authorization catalog and grant it to `admin` (not analyst/read-only)
- [ ] 3.3 Detection operator handler: `GET/POST/PUT/DELETE` destinations, `POST` test-send, `GET` delivery status, each gated via `identityapi.HTTPGate` on `webhook.manage`; register on the operator-session + CSRF allowlist
- [x] 3.4 Save-time validation: reject non-https URLs and hosts that resolve only to a blocked address (see task 6)

## 4. Enqueue hook (transactional outbox)

- [x] 4.1 In the alert insert path (`server/detection/internal/mysql/alerts.go`), inside the existing transaction and only when a new alert is persisted, select enabled destinations whose event-type filter includes the created event and whose minimum severity the alert meets, and insert one `webhook_delivery` row each; the unique key makes a deduplicated alert a no-op
- [x] 4.2 Wrap the alert status-update path in a transaction and enqueue one status-change delivery per matching subscribed destination in the same transaction
- [x] 4.3 Integration test against real MySQL: enqueue-on-create, no-enqueue-when-none, dedup no-double, status-change enqueue

## 5. Payload wire shape

- [x] 5.1 Define the versioned envelope type (event id, event type, occurred_at, delivery_attempt, alert fields, host, process, console link; previous_status on status change); no secret or credential in the body
- [x] 5.2 PBT round-trip (`Marshal ∘ Unmarshal == identity`) with `pgregory.net/rapid`, plus an example-based wire pin of the created and status-change shapes
- [x] 5.3 Console link derived from the deployment external URL (base URL wired via bootstrap; empty yields a relative link)

## 6. SSRF-safe egress

- [x] 6.1 Resolver-and-validator helper: reject/flag any resolved address in loopback, RFC1918 private, RFC 6598 CGNAT, link-local (incl. the instance-metadata address), or unique-local ranges (handles IPv4-mapped IPv6)
- [x] 6.2 HTTP client with a custom dial that connects only to a validated address, uses no environment proxy, and does not follow redirects; per-attempt request timeout and bounded response read
- [x] 6.3 Unit tests: reject http on save, reject private-resolving literal on save, block metadata address at dial time, do-not-follow redirect

## 7. Delivery worker

- [x] 7.1 Add a delivery runner to the detection pipeline; lease due `pending` rows across replicas via `FOR UPDATE OF ... SKIP LOCKED` (no in-process state, no leader lock) so each attempt is taken once
- [x] 7.2 Sign each request HMAC-SHA256 over `id.timestamp.body` with `Webhook-Id`/`Webhook-Timestamp`/`Webhook-Signature` headers, the signature value formatted `v1,<base64>` (Standard Webhooks)
- [x] 7.3 On non-2xx or transport error, schedule exponential backoff up to the attempt cap, then mark `failed`; on 2xx mark `delivered`; record last status/error
- [x] 7.4 Wire the worker beside the existing background workers via detection bootstrap (started from `main.go` `runDetection`); clean ctx-cancel shutdown; keyring label `edr/webhook/secret-seal/v1`
- [ ] 7.5 Record delivery attempts/successes/failures through the existing OTel meter pipeline (follow-up; DB delivery-status is the operable signal for MVP)
- [x] 7.6 Integration test against real MySQL: 5xx-then-2xx redelivery, fail-after-cap (hung-receiver timeout covered by the client timeout; stable delivery id across attempts)

## 8. Config knobs

- [ ] 8.1 Add worker cadence, base backoff, attempt cap, request timeout, and max response size to `server/config/config.go` with a `loadWebhookConfig` helper (follow-up; MVP uses conservative pipeline defaults)

## 9. UI

- [ ] 9.1 `ui/src/permissions-core.ts`: add `WebhookManage` constant
- [ ] 9.2 `ui/src/api.ts`: `listWebhooks`, `createWebhook`, `updateWebhook`, `deleteWebhook`, `testWebhook`, `getWebhookDeliveryStatus` (CSRF on mutations); secret write-only in the request types
- [ ] 9.3 `ui/src/components/Webhooks/Webhooks.tsx` + `.scss`: list, add/edit form (write-only secret), disable/delete, test button with outcome, delivery-health readout; model on `SSOSettings.tsx`
- [ ] 9.4 Add the section to `SettingsLayout.tsx` (`/admin/settings/webhooks`, gated on `WebhookManage`) and the route to `App.tsx` behind `RequirePermission`
- [ ] 9.5 Vitest: add-destination flow, test-send outcome, section hidden without grant, write-only secret field; add the `web-ui` spectrace marker

## 10. Docs + traceability + gates

- [ ] 10.1 Document the receiver-side signature verification (header names, signed content, timestamp tolerance, dedup on event id) and the payload schema for integrators
- [x] 10.2 Add `spec:` markers tying backend tests to this change's delta scenarios (`alert-webhook-delivery`, `server-identity-authorization`); UI `web-ui` markers land with the UI
- [x] 10.3 `openspec validate add-outbound-alert-webhook --strict`; `go run ./tools/spectrace check`
- [ ] 10.4 `go test ./server/...`, `go vet -tags integration ./...`, `task lint:go`, `task lint:dashes`, `cd ui && npm test` (backend + lint done; UI pending)
- [ ] 10.5 Manual QA on the dev server (Chrome MCP): configure a destination pointing at a local receiver, fire an alert, confirm the signed POST arrives and verifies, confirm the delivery-status readout, and confirm an internal URL is refused
