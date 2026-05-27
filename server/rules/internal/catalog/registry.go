package catalog

import "github.com/fleetdm/edr/server/rules/api"

// New returns every detection rule the server registers with the engine, in the canonical registration order, minus any rule
// whose ID() appears in opts.DisabledRuleIDs. Single source of truth for the docs generator (tools/gen-rule-docs), the
// all_rules_integration_test harness, and the production server's main.go -- keeping them in sync prevents docs/runtime drift.
//
// Pass the zero value of api.RegistryOptions for non-production callers (docs generator, tests). Production main.go threads
// the operator-configured allowlists + DisabledRuleIDs through.
//
// DisabledRuleIDs filtering happens here (not in bootstrap or in the engine) so the same disable applies to every consumer
// of catalog.New: a rule the operator disabled is also absent from the GET /api/rules surface (operator visibility) AND from
// tools/gen-rule-docs (markdown drift). Boot-time only -- callers that want to disable + re-enable at runtime must rebuild
// catalog.New with new opts and reload via Engine.LoadActive, which is exactly what restart does.
func New(opts api.RegistryOptions) []api.Rule {
	all := []api.Rule{
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
	if len(opts.DisabledRuleIDs) == 0 {
		return all
	}
	disabled := make(map[string]struct{}, len(opts.DisabledRuleIDs))
	for _, id := range opts.DisabledRuleIDs {
		disabled[id] = struct{}{}
	}
	filtered := make([]api.Rule, 0, len(all))
	for _, r := range all {
		if _, drop := disabled[r.ID()]; drop {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// UnknownDisabledIDs returns the entries of opts.DisabledRuleIDs that did NOT match the ID() of any rule in the production
// registry. Callers (notably rules.bootstrap.New) use this to warn at boot when a stale operator config references a rule
// that has since been renamed or removed. Returns nil for an empty / all-matched disable list. Computing the known-ID set
// walks New(zero) once per call; the work is O(rules + disabled) and runs once at boot, so the extra pass is negligible.
func UnknownDisabledIDs(opts api.RegistryOptions) []string {
	if len(opts.DisabledRuleIDs) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(opts.DisabledRuleIDs))
	for _, r := range New(api.RegistryOptions{}) {
		known[r.ID()] = struct{}{}
	}
	var unknown []string
	for _, id := range opts.DisabledRuleIDs {
		if _, ok := known[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	return unknown
}
