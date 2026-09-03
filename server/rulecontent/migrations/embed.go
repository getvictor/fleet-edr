// Package migrations embeds the rulecontent context's goose migrations, applied by
// bootstrap.ApplySchema against the rulecontent_goose_db_version tracking table.
package migrations

import "embed"

// FS holds the .sql migration files for the rulecontent context.
//
//go:embed *.sql
var FS embed.FS
