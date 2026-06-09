package main

import (
	"embed"
	"fmt"
	"io/fs"

	"sigs.k8s.io/yaml"

	"github.com/fleetdm/edr/test/fakeagent"
)

// corpusFS holds the attack scenarios woven into the rich captured hosts (see hosts.go). The files are local copies of
// test/efficacy/corpus entries plus the two demo-only scenarios (app-control-blocked-app.yaml and dns-c2-beacon.yaml) that
// fakeagent-replayed attacks need. They are no longer replayed as standalone hosts; each is re-hosted onto a captured host by
// the seeder so the detection fires inside genuine ambient activity rather than in a 2-event vacuum.
//
//go:embed corpus/*.yaml
var corpusFS embed.FS

// scenarioKind classifies how the seeder weaves an attack onto a host after replaying its events.
type scenarioKind string

const (
	// kindAttack scenarios are expected to trip a catalog rule (ExpectRule names it) once posted.
	kindAttack scenarioKind = "attack"
	// kindAppControl scenarios materialise the process a follow-up application_control_block event refers to; the seeder posts
	// that block event itself (fakeagent does not emit application_control_block).
	kindAppControl scenarioKind = "app_control"
)

// loadAttackScenario reads, parses, and validates a single embedded attack scenario. A parse/validation failure is a build-time
// bug (the files are checked in), so it returns an error rather than skipping.
func loadAttackScenario(file string) (*fakeagent.Scenario, error) {
	raw, err := fs.ReadFile(corpusFS, "corpus/"+file)
	if err != nil {
		return nil, fmt.Errorf("read embedded corpus %s: %w", file, err)
	}
	return decodeAttackScenario(raw, file)
}

// decodeAttackScenario parses and validates one scenario's raw YAML. Split from the embed read so the parse/validate failure
// paths are unit-testable without a checked-in malformed fixture.
func decodeAttackScenario(raw []byte, name string) (*fakeagent.Scenario, error) {
	var sc fakeagent.Scenario
	// Strict decode: an unknown or misspelled YAML key is a checked-in-corpus bug, not something to silently default away (a
	// typo'd field would otherwise produce a low-fidelity scenario that still parses). The files ship in the binary, so any
	// drift is caught at build time by the tests that load every scenario.
	if err := yaml.UnmarshalStrict(raw, &sc); err != nil {
		return nil, fmt.Errorf("parse corpus %s: %w", name, err)
	}
	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("validate corpus %s: %w", name, err)
	}
	return &sc, nil
}

// firstExec returns the pid and path of the first exec event in the scenario. The app-control flow uses it to target the
// follow-up block event at the process the scenario just materialised (after pid offsetting, this is the offset pid).
func firstExec(sc *fakeagent.Scenario) (pid int, execPath string, ok bool) {
	for _, ev := range sc.Timeline {
		if ev.Type == "exec" {
			return ev.PID, ev.Path, true
		}
	}
	return 0, "", false
}
