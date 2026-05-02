// Package mysql owns the commands table. Was previously
// server/store/command.go; phase 4 of the modular-monolith migration
// moved it here. The package's only job is row I/O -- status
// transition validation, audit logging, and HTTP shape live one
// layer up in internal/service/.
package mysql
