package catalog

import "github.com/fleetdm/edr/server/rules/api"

// New returns every detection rule the server registers with the
// engine, in the canonical registration order. Single source of truth
// for the docs generator (tools/gen-rule-docs), the
// all_rules_integration_test harness, and the production server's
// main.go -- keeping them in sync prevents docs/runtime drift.
//
// Pass the zero value of api.RegistryOptions for non-production
// callers (docs generator, tests). Production main.go threads the
// operator-configured allowlists through.
func New(opts api.RegistryOptions) []api.Rule {
	return []api.Rule{
		&SuspiciousExec{AllowedNonShellParents: opts.SuspiciousExecParentAllowlist},
		&PersistenceLaunchAgent{AllowedPlists: opts.LaunchAgentAllowlist},
		&DyldInsert{},
		&ShellFromOffice{},
		&OsascriptNetworkExec{},
		&CredentialKeychainDump{},
		&PrivilegeLaunchdPlistWrite{AllowedTeamIDs: opts.LaunchDaemonTeamIDAllowlist},
		&SudoersTamper{AllowedWriters: opts.SudoersWriterAllowlist},
		&ApplicationControlBlock{},
	}
}
