# Self-validating signed host tokens

## Why

Agent auth was an opaque bearer token verified by a per-request database lookup (SHA-256 token-id fetch + keyed-HMAC compare). At fleet scale that lookup is the dominant per-request auth cost: every event upload and command poll pays a DB round-trip just to resolve the token to a host_id. The model also relied on server-driven verify-time rotation plus a grace window and a pushed `rotate_token` command, which is complex and ties the agent's bearer to a server-issued opaque value.

This change makes the host token self-validating: it carries its own identity (`host_id`), an epoch, and an expiry, signed with a server-held HMAC key. Verification becomes a local signature + expiry check with no database access. Tokens are short-lived (default 60m) and the agent pulls a fresh one before expiry via a new refresh endpoint, so a live host never lapses. Revocation moves to a per-replica in-memory snapshot keyed on `token_epoch` + `revoked_at`, refreshed on a short ticker, so a kill switch stays effectively immediate without a per-request DB read. Transport gains HTTP/2 keep-alive PINGs on the agent so a long-lived connection survives sleep/NAT rebinds.

This is a hard cutover: no dual-accept. Pre-existing opaque tokens fail signature verification, 401, and the affected hosts re-enroll through the existing re-enrollment-on-revocation path. The server-driven verify-time auto-rotation, the previous-token grace window, and the `rotate_token` command are removed; operator "rotate" now bumps `token_epoch` (the agent re-enrolls).

## What changes

- New `internal/signedtoken` package: mint + verify a `v1.<payload>.<mac>` token (HMAC-SHA256, claims `hid/ep/iat/exp/kid`, constant-time compare).
- `VerifyToken` is signature + expiry + revocation-snapshot only; no DB lookup, no auto-rotation.
- `Enroll` mints a signed token; the enroll response gains `expires_at`.
- New `POST /api/token/refresh` (behind the host-token middleware) mints a fresh token for the authenticated host; the agent refreshes at ~2/3 of the token lifetime.
- New `token_epoch` column; new per-replica `revocation` snapshot (loaded at boot, refreshed every 5s) enforces revoked + epoch-bumped hosts. Operator rotate bumps the epoch.
- Signing key derived from `EDR_SECRET_KEY` via HKDF under a new label (no new config). `EDR_HOST_TOKEN_LIFETIME` default changes from 24h to 60m; `EDR_HOST_TOKEN_GRACE` is retained but no longer consumed.
- Agent persists `expires_at`, runs a proactive refresh loop, and enables HTTP/2 keep-alive PINGs.

Not in scope: mTLS (the eventual hardening upgrade), removing the now-unused lower-level rotation store methods + the agent's dead `rotate_token` handler (a fast-follow cleanup), removing the vestigial `host_token_id`/`host_token_hash` columns.

## Impact

- Behavior change to agent auth: revocation is now eventually consistent across replicas, bounded by the snapshot refresh interval (default 5s), rather than immediate-on-the-same-replica.
- Breaking for in-flight tokens: a hard cutover triggers a one-time fleet-wide re-enroll on deploy. Acceptable at pilot scale; documented for operators.
- Affected: `server/endpoint` (api, service, store, bootstrap, middleware, new token + revocation + signedtoken packages, migration), `server/config`, both server binaries, `agent/enrollment`, `agent/cmd/fleet-edr-agent`.
