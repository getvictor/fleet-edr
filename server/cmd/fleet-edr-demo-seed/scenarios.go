package main

import (
	"embed"
	"fmt"
	"io/fs"

	"sigs.k8s.io/yaml"

	"github.com/fleetdm/edr/test/fakeagent"
)

// corpusFS holds the curated scenario set replayed into the demo database. The files are local copies of test/efficacy/corpus +
// test/efficacy/noise (go:embed cannot reach those from another module subtree) plus app-control-blocked-app.yaml, which is
// demo-only because fakeagent does not emit application_control_block events.
//
//go:embed corpus/*.yaml
var corpusFS embed.FS

// scenarioKind classifies what the seeder does with each scenario after replaying its events.
type scenarioKind string

const (
	// kindAttack scenarios are expected to trip a catalog rule (ExpectRule names it).
	kindAttack scenarioKind = "attack"
	// kindNoise scenarios are benign: they enrich the process graph and must NOT produce alerts.
	kindNoise scenarioKind = "noise"
	// kindAppControl scenarios materialise the process that a follow-up application_control_block event refers to.
	kindAppControl scenarioKind = "app_control"
)

// demoScenario pairs a curated corpus file with its kind, the catalog rule an attack scenario should fire, and the parsed scenario.
type demoScenario struct {
	File       string
	Kind       scenarioKind
	ExpectRule string
	Scenario   *fakeagent.Scenario
}

// corpusManifest is the ordered, curated demo set. Order is the replay order; it is also the order hosts appear in the demo UI.
var corpusManifest = []demoScenario{
	{File: "keychain-dump.yaml", Kind: kindAttack, ExpectRule: "credential_keychain_dump"},
	{File: "sudoers-tamper.yaml", Kind: kindAttack, ExpectRule: "sudoers_tamper"},
	{File: "launchagent-persistence.yaml", Kind: kindAttack, ExpectRule: "persistence_launchagent"},
	{File: "noise-developer-workstation.yaml", Kind: kindNoise},
	{File: "app-control-blocked-app.yaml", Kind: kindAppControl},
}

// loadScenarios reads, parses, and validates every embedded scenario named in corpusManifest. A parse or validation failure is a
// build-time bug (the files are checked in), so it returns an error rather than skipping.
func loadScenarios() ([]demoScenario, error) {
	out := make([]demoScenario, 0, len(corpusManifest))
	for _, entry := range corpusManifest {
		raw, err := fs.ReadFile(corpusFS, "corpus/"+entry.File)
		if err != nil {
			return nil, fmt.Errorf("read embedded corpus %s: %w", entry.File, err)
		}
		var sc fakeagent.Scenario
		if err := yaml.Unmarshal(raw, &sc); err != nil {
			return nil, fmt.Errorf("parse corpus %s: %w", entry.File, err)
		}
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("validate corpus %s: %w", entry.File, err)
		}
		entry.Scenario = &sc
		out = append(out, entry)
	}
	return out, nil
}

// firstExec returns the pid and path of the first exec event in the scenario. The app-control flow uses it to target the
// follow-up block event at the process the scenario just materialised.
func firstExec(sc *fakeagent.Scenario) (pid int, execPath string, ok bool) {
	for _, ev := range sc.Timeline {
		if ev.Type == "exec" {
			return ev.PID, ev.Path, true
		}
	}
	return 0, "", false
}
