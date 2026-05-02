// Package policy owns the policies table. A single "default" row holds
// the current version + serialised blocklist payload. Update bumps the
// version atomically inside a transaction and returns the new row.
//
// The package deliberately does NOT depend on the command queue or the
// catalog: callers (rules/internal/service) compose Get + Update with a
// fan-out pass. This keeps the policy code easy to test without mocking
// commands.
package policy
