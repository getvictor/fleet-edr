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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		holds, err := holdsMigrations(filepath.Join(serverDir, e.Name(), "migrations"))
		if err != nil {
			return nil, fmt.Errorf("read %s migrations: %w", e.Name(), err)
		}
		if holds {
			found = append(found, e.Name())
		}
	}
	sort.Strings(found)
	return found, nil
}

// holdsMigrations reports whether dir contains at least one migration file.
//
// A directory read rather than a glob, and review was right that the difference is reachable. filepath.Glob treats its whole
// argument as a PATTERN, so a checkout under a path containing glob metacharacters silently matches nothing, and it reports no
// error when a directory cannot be read. Either way the scan would report a context as shipping no migrations, both guards would
// have nothing to check, and they would pass at exactly the moment they were needed. Measured: a temp directory named with
// brackets yields zero matches and a nil error.
//
// A missing directory is the ordinary shape of a context that owns no tables, so it is not an error. Anything else is.
func holdsMigrations(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			return true, nil
		}
	}
	return false, nil
}
