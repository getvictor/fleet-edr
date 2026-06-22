// gen-attack-layer renders docs/attack-navigator-layer.json: a MITRE ATT&CK Navigator layer-4.5 document enumerating the
// techniques the detection rule catalog covers. Run via:
//
//	go run ./tools/gen-attack-layer
//
// The layer is built by rulesapi.BuildNavigatorLayer, the same function that backs the live GET /api/attack-coverage endpoint,
// so the committed artifact and the running server cannot drift. Output is deterministic (sorted techniques + covering-rule
// lists, no timestamps) so the file is diff-friendly; a server-side test (TestNavigatorLayerArtifactInSync) fails CI on drift.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

// allRegisteredRules delegates to rules.bootstrap.CatalogOnly so this generator and the production server's main.go walk the same
// set of rules in the same order. Coverage is not a function of a deployment's tuning, so we pass the zero RegistryOptions:
// allowlists default to empty, which the rule structs treat as "no operator tuning yet."
func allRegisteredRules() []rulesapi.RuleMetadata {
	return rulesbootstrap.CatalogOnly().List()
}

func main() {
	out := flag.String("out", "docs/attack-navigator-layer.json", "destination Navigator layer JSON file")
	flag.Parse()

	if err := generate(*out); err != nil {
		log.Fatalf("%v", err)
	}
}

func generate(out string) error {
	b, err := rulesapi.MarshalNavigatorLayerIndented(rulesapi.BuildNavigatorLayer(allRegisteredRules()))
	if err != nil {
		return fmt.Errorf("marshal layer: %w", err)
	}
	// 0o644: the layer is a generated, world-readable documentation artifact committed to the repo, not a secret.
	if err := os.WriteFile(out, b, 0o644); err != nil { //nolint:gosec // generated public doc, path is operator-controlled
		return fmt.Errorf("write %s: %w", out, err)
	}
	return nil
}
