// Package migrations holds the observability bounded context's goose-managed SQL migration corpus, embedded so it can be applied at
// boot by server/migrations/runner without the binary reading from disk.
package migrations

import "embed"

// FS is observability's migration corpus: NNNNN_name.sql files at the FS root. server/observability/bootstrap.ApplySchema passes it
// to runner.Up against the observability_goose_db_version tracking table.
//
//go:embed *.sql
var FS embed.FS
