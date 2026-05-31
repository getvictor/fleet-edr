// Package migrations holds the endpoint bounded context's goose-managed SQL migration corpus, embedded so it can be applied at
// boot by server/migrations/runner without the binary reading from disk.
package migrations

import "embed"

// FS is endpoint's migration corpus: NNNNN_name.sql files at the FS root. server/endpoint/bootstrap.ApplySchema passes it to
// runner.Up against the endpoint_goose_db_version tracking table.
//
//go:embed *.sql
var FS embed.FS
