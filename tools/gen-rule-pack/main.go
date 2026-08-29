// gen-rule-pack writes one declarative rule file per registered detection (issue #757). Run via:
//
//	go run ./tools/gen-rule-pack
//
// Output is deterministic (one file per rule, no timestamps, stable key order) so the pack is diff-friendly and CI-checkable, the
// same contract gen-rule-docs holds for docs/detection-rules.md.
//
// Only detections are written. The registry also holds non-detections (a projection of an agent-side decision, a health signal
// about our own agent), and those are absent from the catalog surface this reads for the reasons issue #775 records: a rule file
// for something with no detection logic and no adversary claim misrepresents all three of what it is, what it can be tuned to do,
// and what it covers.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
)

func main() {
	outDir := flag.String("out", "server/rules/internal/catalog/pack", "destination directory for the rule pack")
	flag.Parse()

	written, err := generate(*outDir)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("wrote %d rule files to %s", written, *outDir)
}

// generate renders every registered detection into outDir and returns how many files it wrote.
//
// It renders every rule before writing any of them. A partial pack is the failure mode worth avoiding here: half-written output
// looks like a real pack to the next reader and to CI's drift check, whereas an error with nothing written is unambiguous.
func generate(outDir string) (int, error) {
	pack, err := rulesbootstrap.ExportPack()
	if err != nil {
		return 0, fmt.Errorf("render pack: %w", err)
	}
	if len(pack) == 0 {
		return 0, errors.New("no detections registered; refusing to write an empty pack")
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return 0, fmt.Errorf("create %s: %w", outDir, err)
	}
	for id, body := range pack {
		path := filepath.Join(outDir, id+".yml")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			return 0, fmt.Errorf("write %s: %w", path, err)
		}
	}
	if err := prune(outDir, pack); err != nil {
		return 0, err
	}
	return len(pack), nil
}

// prune removes rule files for rules that are no longer registered.
//
// Without it, deleting or renaming a detection leaves its file behind, the drift check fails on the extra file, and the failure
// message tells the developer to run the very command that will not remove it. Only `.yml` files are considered, so the
// directory's README survives.
func prune(outDir string, pack map[string][]byte) error {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", outDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		// The shared-list definitions live in the pack but are authored, not generated. Without this the first regeneration
		// after they were added deleted them, which is how this guard came to exist.
		if e.Name() == rulesbootstrap.PackSharedListsFile {
			continue
		}
		if _, registered := pack[strings.TrimSuffix(e.Name(), ".yml")]; registered {
			continue
		}
		path := filepath.Join(outDir, e.Name())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove obsolete %s: %w", path, err)
		}
		log.Printf("removed obsolete %s", path)
	}
	return nil
}
