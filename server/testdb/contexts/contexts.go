// Package contexts reports which bounded contexts ship database migrations, by reading the source tree.
//
// It exists so the guards that check context registration share one definition of "a context that ships migrations". Two copies
// of that rule can disagree, and then the migrator's gate and the test fixture's gate would police different sets: the exact
// class of defect those gates exist to catch, one level up. Review caught the duplication that prompted this package.
//
// Reading the tree rather than holding a list is the whole point. A hardcoded expectation is not a check: a context added without
// registering it would be missing from the expectation too, and the test would agree with the bug.
package contexts

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// MySQLMigrations lists the bounded contexts under serverDir that ship MySQL migrations, sorted.
//
// MySQL specifically, and the narrowness is deliberate. The standalone migrator takes a MySQL DSN only, and one context keeps a
// separate ClickHouse corpus that the server applies at boot instead (ADR-0015). A guard that counted that corpus would demand
// the migrator apply something it cannot reach.
func MySQLMigrations(serverDir string) ([]string, error) {
	entries, err := os.ReadDir(serverDir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", serverDir, err)
	}
	var found []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sqls, err := filepath.Glob(filepath.Join(serverDir, e.Name(), "migrations", "*.sql"))
		if err != nil {
			return nil, fmt.Errorf("glob %s migrations: %w", e.Name(), err)
		}
		if len(sqls) > 0 {
			found = append(found, e.Name())
		}
	}
	sort.Strings(found)
	return found, nil
}
