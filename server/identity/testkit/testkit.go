// Package testkit is identity's coordinated test-fixture surface.
//
// Tests reach for testkit; production wiring (cmd/main, server/testdb/full,
// test/integration) reaches for bootstrap. The two contracts are
// deliberately separate: bootstrap is for standing up real wiring;
// testkit is for tests that need just enough of identity to exercise
// some other piece (the users table, a stub User existence check, etc.)
// without spinning up the full Identity service.
//
// Today the package only exposes ApplySchema. As cross-context tests
// grow, this is the right home for identity-specific seeders
// (e.g. SeedUser) and fakes (e.g. UserExistsAlways) so each test file
// stops re-implementing them.
//
// Constraint: this package must NOT import any other bounded context.
// arch-go pins the rule. Cross-context fixture composition is
// server/testdb/full's job, not testkit's.
package testkit

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/bootstrap"
)

// ApplySchema runs identity's DDL + idempotent ALTERs against db.
// Thin wrapper over bootstrap.ApplySchema so the test surface is
// importable separately from the production wiring surface.
func ApplySchema(ctx context.Context, db *sqlx.DB) error {
	return bootstrap.ApplySchema(ctx, db)
}

// AllowAllAuthZ implements api.AuthZ as an unconditional grant. Used
// by tests that need a chokepoint dependency satisfied but are not
// exercising the role matrix; the real engine's per-action behaviour
// is covered exhaustively in the authz package's own tests, so making
// every cross-context test compile + recompile a Rego bundle is
// avoidable overhead.
type AllowAllAuthZ struct{}

// Allow satisfies api.AuthZ; always returns Decision{Allow: true,
// Reason: "granted"}.
func (AllowAllAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	return api.Decision{Allow: true, Reason: "granted"}, nil
}

// DenyAuthZ implements api.AuthZ with a fixed deny reason. Used by
// handler tests that exercise the deny-path response shape (403 +
// X-Edr-Authz-Reason header) without depending on the live policy.
type DenyAuthZ struct {
	Reason string
}

// Allow satisfies api.AuthZ; returns Decision{Allow: false} with the
// configured reason. Default reason "no_matching_rule" matches the
// production policy's deny label so tests that pin the header value
// stay in sync with the live decision shape.
func (d DenyAuthZ) Allow(context.Context, api.Action, api.Resource) (api.Decision, error) {
	r := d.Reason
	if r == "" {
		r = "no_matching_rule"
	}
	return api.Decision{Allow: false, Reason: r}, nil
}
