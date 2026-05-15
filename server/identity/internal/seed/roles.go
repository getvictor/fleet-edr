package seed

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// BuiltinRole is one of the five seeded RBAC roles. The string values
// are stable wire shapes referenced from OPA / Rego policy bundles and
// from role-binding rows; renaming a constant here is a schema-level
// break.
type BuiltinRole struct {
	ID          string
	DisplayName string
	Description string
}

// BuiltinRoles is the deployment's seeded role set. The order is
// stable so audit logs of the seed step (and tests that introspect
// the table) read consistently. Permission grants for each role live
// in the OPA policy bundle the future AuthZ engine evaluates; this
// list only names the roles and flags them as non-deletable.
//
// super_admin: the highest tier. Owns deployment + SSO config plus
// every permission below; the break-glass account binds to this role
// at the deployment-wide (global) scope.
//
// admin: day-to-day administration -- user invitations, policy
// authoring, every host action, every alert action. Cannot reach
// deployment / SSO config.
//
// senior_analyst: investigate and take destructive action --
// host.isolate, host.kill_process, host.run_script, the full alert
// lifecycle. Can read but not author policy.
//
// analyst: investigate, comment, escalate -- host.read, process.read,
// alert.read, alert.comment. Default for SSO-provisioned users; the
// system MUST NOT auto-elevate from any SSO claim.
//
// auditor: read-only including audit.read. Used by SOC analysts who
// need the full investigative read surface plus the audit trail
// without any ability to mutate state.
var BuiltinRoles = []BuiltinRole{
	{
		ID:          "super_admin",
		DisplayName: "Super Admin",
		Description: "Deployment + SSO configuration plus every other role's permissions. " +
			"The break-glass account binds here at the deployment-wide scope.",
	},
	{
		ID:          "admin",
		DisplayName: "Admin",
		Description: "Day-to-day administration: user invitations, policy authoring, " +
			"every host action, every alert action. No deployment / SSO config.",
	},
	{
		ID:          "senior_analyst",
		DisplayName: "Senior Analyst",
		Description: "Investigate and take destructive action: host.isolate, " +
			"host.kill_process, host.run_script, full alert lifecycle.",
	},
	{
		ID:          "analyst",
		DisplayName: "Analyst",
		Description: "Investigate, comment, escalate: host.read, process.read, " +
			"alert.read, alert.comment. Default for SSO-provisioned users.",
	},
	{
		ID:          "auditor",
		DisplayName: "Auditor",
		Description: "Read-only across the investigative surface plus audit.read. " +
			"For SOC review without any mutation permissions.",
	},
}

// Roles seeds the `roles` table with the five built-in roles. Idempotent
// via INSERT IGNORE: a populated DB is a no-op; an empty DB inserts
// every row. is_builtin is set to 1 so the future admin API can refuse
// to delete them; an operator who wants a different name can edit
// display_name or description in place because INSERT IGNORE preserves
// whatever's there.
func Roles(ctx context.Context, db *sqlx.DB) error {
	if db == nil {
		return errors.New("seed.Roles: db must not be nil")
	}
	for _, r := range BuiltinRoles {
		_, err := db.ExecContext(ctx, `
			INSERT IGNORE INTO roles (id, display_name, description, is_builtin)
			VALUES (?, ?, ?, 1)
		`, r.ID, r.DisplayName, r.Description)
		if err != nil {
			return fmt.Errorf("seed role %q: %w", r.ID, err)
		}
	}
	return nil
}
