// Package migrations holds the identity bounded context's goose-managed SQL migration corpus, embedded so it can be applied at
// boot by server/migrations/runner without the binary reading from disk.
package migrations

import "embed"

// FS is identity's migration corpus: NNNNN_name.sql files at the FS root. server/identity/bootstrap.ApplySchema passes it to
// runner.Up against the identity_goose_db_version tracking table, then seeds the built-in roles.
//
//go:embed *.sql
var FS embed.FS
