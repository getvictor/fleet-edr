// Package service implements identity/api.Service by composing the users
// store, sessions store, and seeder into a single orchestrator. The HTTP
// handlers in identity/internal/login call into this package for the
// business logic of login / logout / who-am-i; cross-context callers (e.g.
// detection's alert-update handler) call UserExists through the
// public api.Service interface.
//
// Internal to the identity bounded context. Do not import from outside
// server/identity/.
package service
