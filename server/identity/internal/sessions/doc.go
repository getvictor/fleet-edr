// Package sessions owns the `sessions` table that backs UI cookie auth. A session is a server-side row keyed by the SHA-256 digest of a
// 32-byte random token. The cookie carries the raw token (base64url-encoded);
// the DB stores only the digest, mirroring the pattern enrollment tokens use
// so a database compromise does not immediately yield replayable bearer
// credentials.
//
// Internal to the identity bounded context. Do not import from outside
// server/identity/.
package sessions
