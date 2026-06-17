# Agent enrollment: host-token fast keyed hash delta

## ADDED Requirements

### Requirement: Host tokens are stored and verified with a fast keyed hash

The server SHALL store each issued host token as a keyed HMAC-SHA256 of the token under a server-held secret pepper, and SHALL NOT store the token in plaintext, reversibly encrypted, or under a memory-hard password KDF (argon2id, bcrypt, scrypt). The server SHALL verify a presented token by recomputing HMAC-SHA256 under the same pepper and comparing the result to the stored value with a constant-time equality check. Because the host token is a high-entropy random secret (not a human-chosen password), a fast keyed hash gives the same practical resistance to offline recovery as a slow KDF while removing the per-request hashing cost from the authenticated agent hot path. The server SHALL continue to fetch the candidate enrollment row by the deterministic SHA-256 token-id lookup key, so verification reads a single indexed row rather than scanning active enrollments.

The pepper SHALL be derived from a single required server root secret (`EDR_SECRET_KEY`, with the standard `*_FILE` fallback) using HKDF-SHA256 under a fixed versioned domain-separation label, rather than provisioned as its own secret; the server SHALL refuse to boot when the root secret is absent. Rotating or changing the root secret (or the pepper's derivation label) invalidates every existing host token, which is an accepted operator-initiated fleet-wide re-enroll, not a routine action.

This change is breaking and ships no token re-hash migration: enrollment rows created before the change hold a value that is not an HMAC of any presented token, so those tokens SHALL fail verification and the affected hosts SHALL recover through the existing re-enrollment-on-revocation path.

#### Scenario: Issued token is stored as a keyed hash

- **GIVEN** a host completes enrollment and the server issues an opaque host token
- **WHEN** the server persists the enrollment row
- **THEN** the stored authenticator is HMAC-SHA256 of the token under the server pepper
- **AND** no plaintext token and no per-row salt is stored
- **AND** the row also carries the SHA-256 token-id as the indexed lookup key

#### Scenario: Verification on the authenticated hot path

- **GIVEN** an enrolled host presents its valid host token in an Authorization Bearer header
- **WHEN** the server authenticates the request
- **THEN** the server fetches the enrollment row by the token-id lookup key
- **AND** recomputes HMAC-SHA256 of the presented token under the server pepper
- **AND** accepts the request when the recomputed value matches the stored value under a constant-time compare

#### Scenario: A token that does not match is rejected

- **GIVEN** an enrollment row whose stored authenticator is not the HMAC of the presented token, including any row hashed under a different pepper or created before this change
- **WHEN** the host presents that token
- **THEN** the server rejects the request with 401
- **AND** the host re-enrolls using the deployment secret through the re-enrollment-on-revocation path
