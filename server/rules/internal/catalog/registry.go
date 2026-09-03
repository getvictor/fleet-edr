package catalog

import "github.com/fleetdm/edr/server/rules/api"

// NewWithCorpus returns every detection rule the server registers with the engine, in the canonical registration order: the
// compiled-in detections followed by the supplied corpus. Taking the corpus as a parameter is how content loaded from storage
// reaches the catalog (issue #766); see New for the form that uses the corpus embedded in the build.
//
// Single source of truth for the docs generator (tools/gen-rule-docs), the all_rules_integration_test harness, and the production
// server's main.go: keeping them in sync prevents docs/runtime drift.
//
// resolver is the per-host false-positive exclusion resolver (issue #459) the rules that support exclusions consult before firing;
// pass nil for non-production callers (docs generator, tests with no configured exclusions), which excludes nothing.
//
// Rules are NEVER filtered out here: enabling/disabling a rule is now per-host configuration resolved at evaluation time by the
// detection engine (a globally-disabled rule stays visible in GET /api/rules and simply emits nothing), so the catalog always
// returns the full set.
func NewWithCorpus(resolver api.ExclusionResolver, corpus []api.Rule) []api.Rule {
	// Force the pack and shared lists to load here, so a malformed file fails at start-up. The rules read their values through
	// lazily-memoized accessors, which are otherwise first touched during evaluation: without this a bad value would let the
	// server boot and then panic on the first detection, which is precisely what validating at load exists to prevent.
	MustLoadPack()
	MustLoadDetections()

	rules := []api.Rule{
		&SuspiciousExec{Exclusions: resolver},
		&ShellNetworkConnect{Exclusions: resolver},
		&PersistenceLaunchAgent{Exclusions: resolver},
		&DyldInsert{},
		&ShellFromOffice{},
		&OsascriptNetworkExec{},
		&CredentialKeychainDump{},
		&PrivilegeLaunchdPlistWrite{Exclusions: resolver},
		&SudoersTamper{Exclusions: resolver},
		&ApplicationControlBlock{},
		&DNSC2Beacon{},
		&SensorTamper{},
		&SensorRecoveryFailed{},
	}
	// The imported corpus is appended rather than interleaved so registration order still reads as "what this project wrote,
	// then what it vendored", which is the order the operator-facing catalog and the docs are generated in.
	return append(rules, corpus...)
}

// New returns the catalog as it ships: the compiled-in detections plus the VENDORED corpus embedded in the binary.
//
// Kept as the default because it is what tooling, tests, and a deployment with no stored corpus want, and because the embedded
// corpus is a build artifact whose failure to load is a build problem (hence the panic inside). NewWithCorpus is the form that
// takes a corpus loaded from storage, where a load failure is a runtime condition with a different answer (issue #766).
func New(resolver api.ExclusionResolver) []api.Rule {
	return NewWithCorpus(resolver, MustLoadImported())
}
