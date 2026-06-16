// Package mysql owns the `enrollments` table that backs agent
// authentication. The Store exposes Register / Verify / List /
// Get / Revoke / CountActive / ActiveHostIDs. The host-token bytes are
// hashed via keyed HMAC-SHA256 (see hash.go) before persistence so a
// database dump does not yield replayable bearer credentials.
//
// Internal to the endpoint bounded context. Do not import from outside
// server/endpoint/.
package mysql
