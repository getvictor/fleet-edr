# Design notes

## Outbox model: fan out at enqueue

Two shapes were considered. Fan out at send keeps one row per alert event and lets the delivery worker resolve destinations at send time. Fan out at enqueue writes one row per (alert event, destination) at alert-creation time, so each outbox row is a self-contained delivery with its own attempt count, status, and next-attempt time.

Decision: fan out at enqueue. It is the classic transactional outbox and it keeps per-destination retry state trivial (each row is one delivery). Reading the enabled destinations inside the alert transaction is cheap because the destinations table is small. The accepted trade-off is that a destination added after an alert fired does not receive past alerts, which matches how webhooks are expected to behave (forward-looking, not backfilled). The outbox row is keyed unique on (alert id, event type, destination id) so a retried enqueue (for example an alert dedup that touches the same row) cannot create a duplicate delivery.

## Context ownership: everything lives in the detection context

The outbox row must be written in the same transaction as the alert insert (`server/detection/internal/mysql/alerts.go`), and cross-context table sharing is disallowed (ADR-0004: cross-context calls go through the imported `api/` package). Therefore both the destinations table and the delivery outbox live in the detection context's schema, the enqueue hook lives in the detection alert paths, the delivery worker lives in the detection pipeline beside the existing runners, and the admin surface is a detection operator surface. This is consistent with the existing detection-config operator surface (exclusions and rule settings). The one identity-owned piece is the `webhook.manage` action in the authorization catalog, consumed through the existing `identityapi.HTTPGate` the detection handlers already use.

## Signing scheme: Standard Webhooks

Adopt the Standard Webhooks convention (standardwebhooks.com): headers `webhook-id`, `webhook-timestamp`, and `webhook-signature: v1,<base64>`, where the signed content is `id.timestamp.body` and the MAC is HMAC-SHA256 under the destination secret. Rationale: receivers get verifier libraries in every major language for free, which directly serves the universal-adapter goal. Binding the timestamp into the signed content is what gives receivers replay protection (reject outside a tolerance window). The signature is over the exact bytes sent, so the payload is serialized once and both signed and transmitted from the same buffer.

## Secret sealing

Reuse the AES-256-GCM sealer that already protects the OIDC client secret (`server/identity/internal/ssoconfig/crypto.go`), keyed from the deployment root secret via the keyring. Per find-prior-art, factor that sealer into a shared internal package so identity and detection use one implementation rather than cloning it. The plaintext secret is accepted only on create and update, is never persisted in plaintext, and is never returned by a read. Each destination has its own secret so compromise of one receiver cannot forge deliveries to another.

## SSRF strategy: authoritative at delivery time

The load-bearing control is at delivery time: on every attempt, resolve the host and validate every resolved address against the blocked ranges (loopback, RFC1918 private, link-local including the cloud instance-metadata address, and unique-local), connect only to a validated address, and do not follow redirects to a blocked target. Delivery-time enforcement is authoritative because DNS can change between save and send (rebinding and time-of-check gaps). The check operates on the parsed IP form so that an IPv4-mapped IPv6 address (for example `::ffff:169.254.169.254`) or another encoding of a blocked address cannot slip past the range test. Save-time validation (reject non-https, reject a host that resolves only to a blocked range) is added on top purely for fast operator feedback. Pinning the socket to the exact validated address to fully close the rebinding window is a deferred hardening step; the per-attempt re-resolve-and-validate already blocks the metadata-credential-theft class.

## Reliability and multi-replica safety (ADR-0010)

The DB outbox is the only delivery state; nothing rides in process memory. Multiple replicas drain the queue concurrently and safely by claiming due rows the same way the detection processor already claims work, so a given delivery attempt is taken by exactly one replica and the queue resumes after any restart with no lost work. Backoff schedules the next attempt as a growing multiple of a base interval, capped; once the attempt cap is reached the delivery is marked failed and surfaced to operators rather than dropped. The event id on each delivery is the stable dedup key receivers use, since delivery is at-least-once.

## Status-change events

The alert status-update path currently issues a direct update. To enqueue the status-change delivery atomically it is wrapped in a transaction so the alert status row and the outbox row commit together, matching the create path.

## Must-have vs deferred

Shipped in this change (a security defect if omitted): HMAC-plus-timestamp signing; per-destination secret sealed at rest and write-only; SSRF egress guards (https-only, resolved-IP denylist, no internal redirects); per-attempt timeout, bounded response, and capped retries; and a minimal delivery-status readout (an enterprise will not trust a webhook whose health it cannot see).

Deferred to unmilestoned follow-ups (improvements, not holes): dual-secret rotation overlap; circuit-breaker auto-disable; static bearer-token auth header; DNS-rebinding connection pinning; mTLS; vendor formatters; SIEM export formats; advanced routing UI.
