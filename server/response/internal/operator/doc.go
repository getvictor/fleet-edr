// Package operator serves the session-gated operator routes:
//
//	POST /api/commands            - admin issues a command for a target host
//	GET  /api/commands/{id}       - admin reads a single command by id
//
// Both routes are wrapped in identity.Session + identity.CSRF
// middleware by cmd/main. Operator audit fields (admin_actor +
// admin_action) populate from the session ctx.
package operator
