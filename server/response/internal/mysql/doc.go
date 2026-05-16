// Package mysql owns the commands table. Earlier server versions kept this in server/store/command.go; the modular-monolith split
// moved it here. The package's only job is row I/O -- status transition validation, audit logging, and HTTP shape live one layer up in
// internal/service/.
package mysql
