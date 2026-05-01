// Package seed bootstraps the first-boot state that is too opinionated for
// DDL: the single admin user that the UI logs in as. Called from the
// identity service's SeedAdmin method, which cmd/main invokes after schema
// is applied and before the HTTP listener binds.
//
// Internal to the identity bounded context. Do not import from outside
// server/identity/.
package seed
