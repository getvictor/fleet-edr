// Package migrationsclickhouse holds the visibility context's ClickHouse migration corpus for the event archive, embedded so it can
// be applied at boot by server/migrations/runner (with runner.DialectClickHouse) without the binary reading from disk.
package migrationsclickhouse

import "embed"

// FS is the event archive's ClickHouse migration corpus: NNNNN_name.sql files at the FS root. server/visibility/bootstrap applies it
// against the visibility_clickhouse_goose_db_version tracking table.
//
//go:embed *.sql
var FS embed.FS
