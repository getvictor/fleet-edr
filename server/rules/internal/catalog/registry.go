package catalog

import "github.com/fleetdm/edr/server/rules/api"

// New returns every detection rule the server registers with the engine, in the canonical registration order. Single source of
// truth for the docs generator (tools/gen-rule-docs), the all_rules_integration_test harness, and the production server's main.go:
// keeping them in sync prevents docs/runtime drift.
//
// resolver is the per-host false-positive exclusion resolver (issue #459) the rules that support exclusions consult before firing;
// pass nil for non-production callers (docs generator, tests with no configured exclusions), which excludes nothing.
//
// Rules are NEVER filtered out here: enabling/disabling a rule is now per-host configuration resolved at evaluation time by the
// detection engine (a globally-disabled rule stays visible in GET /api/rules and simply emits nothing), so the catalog always
// returns the full set.
func New(resolver api.ExclusionResolver) []api.Rule {
	return []api.Rule{
		&SuspiciousExec{Exclusions: resolver},
		&PersistenceLaunchAgent{Exclusions: resolver},
		&DyldInsert{},
		&ShellFromOffice{},
		&OsascriptNetworkExec{},
		&CredentialKeychainDump{},
		&PrivilegeLaunchdPlistWrite{Exclusions: resolver},
		&SudoersTamper{Exclusions: resolver},
		&ApplicationControlBlock{},
		&DNSC2Beacon{},
	}
}
