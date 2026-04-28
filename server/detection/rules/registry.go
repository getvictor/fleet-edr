package rules

import "github.com/fleetdm/edr/server/detection"

// RegistryOptions carries the config knobs that production-side rule
// instances need at construction time. Test code that doesn't care about
// allowlists can pass the zero value to All; the rules then run with empty
// allowlists, which is the documented "no operator tuning yet" mode.
//
// Fields here mirror the relevant ones on server/config.Config; pulling
// just the rule-shaped subset keeps this package free of a dependency on
// the full server config struct (which would create an import cycle the
// moment server/config grows a rules import for any reason).
type RegistryOptions struct {
	SuspiciousExecParentAllowlist map[string]struct{}
	LaunchAgentAllowlist          map[string]struct{}
	LaunchDaemonTeamIDAllowlist   map[string]struct{}
	SudoersWriterAllowlist        map[string]struct{}
}

// All returns every detection rule the server registers with the engine,
// in the canonical registration order. Single source of truth for the
// docs generator (tools/gen-rule-docs), the all_rules_integration_test
// harness, and the production server's main.go — keeping them in sync
// prevents the docs/runtime drift CodeRabbit flagged on PR #58.
//
// Pass the zero value of RegistryOptions for non-production callers
// (docs generator, tests). Production main.go threads the operator-
// configured allowlists through.
func All(opts RegistryOptions) []detection.Rule {
	return []detection.Rule{
		&SuspiciousExec{AllowedNonShellParents: opts.SuspiciousExecParentAllowlist},
		&PersistenceLaunchAgent{AllowedPlists: opts.LaunchAgentAllowlist},
		&DyldInsert{},
		&ShellFromOffice{},
		&OsascriptNetworkExec{},
		&CredentialKeychainDump{},
		&PrivilegeLaunchdPlistWrite{AllowedTeamIDs: opts.LaunchDaemonTeamIDAllowlist},
		&SudoersTamper{AllowedWriters: opts.SudoersWriterAllowlist},
	}
}
