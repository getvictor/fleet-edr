package audit_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditEventsAppendOnly enforces the spec's append-only invariant:
// no production Go source file may emit an UPDATE or DELETE statement
// against the audit_events table. Lefthook runs the same regex against
// staged files at commit time; this test is the second line of defense
// for developers who bypass the hook with --no-verify.
//
// The check is intentionally tolerant of:
//   - test files (*_test.go) — fixtures may insert + truncate to set
//     up scenarios; no production caller does.
//   - vendor/, tmp/, ui/node_modules/ — third-party / scratch.
//   - the schema DDL itself — `CREATE TABLE audit_events` ships in
//     server/identity/bootstrap/schema.go and the regex below
//     deliberately does not match CREATE.
//
// A future archival job (wave-2 retention) would land in its own
// package and need an explicit exception added to the allowed-list,
// at which point the rule's intent is the discussion the change
// invites — exactly the code-review signal the spec wanted.
func TestAuditEventsAppendOnly(t *testing.T) {
	root := repoRoot(t)
	forbidden := regexp.MustCompile(`(?i)\b(update\s+audit_events|delete\s+from\s+audit_events)\b`)

	var violations []string
	require.NoError(t, filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if shouldSkipDir(path, root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if isAuditPackageOwnFile(path, root) {
			// The audit package itself contains the canonical INSERT
			// statement and may legitimately reference audit_events in
			// strings; skip its own files to avoid false positives on
			// schema names embedded in error messages.
			return nil
		}
		// path is fully under the repo root (we walk from there) and
		// the lint is read-only — no file-inclusion risk.
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return err
		}
		if loc := forbidden.FindIndex(data); loc != nil {
			violations = append(violations,
				path+": "+string(data[loc[0]:loc[1]]))
		}
		return nil
	}))

	assert.Empty(t, violations,
		"audit_events is append-only; UPDATE/DELETE found in production source. "+
			"If this is a wave-2 archival job, add an explicit exception in this lint and "+
			"document the package-level rationale.")
}

// repoRoot derives the repository root from this source file's path
// at compile time. runtime.Caller is robust across test runners
// (working dir may be the package dir or the repo root depending on
// how the test is invoked) and OS path separators (filepath.Join
// normalises). Mirrors handler_gate_lint_test.go's approach.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must report this file's path")
	// This file lives at server/identity/internal/audit/<name>_test.go;
	// the repo root is four directories up.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

// shouldSkipDir reports whether walking under dir would scan content
// the lint should not police. Non-Go directories and third-party
// trees are excluded so a transitive dependency mentioning an
// "audit_events" column in its own SQL doesn't fail the build.
func shouldSkipDir(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return false
	}
	first := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
	switch first {
	case ".git", "vendor", "tmp", "node_modules":
		return true
	}
	// Any path containing /node_modules/ (npm workspace nests).
	if strings.Contains(filepath.ToSlash(rel), "/node_modules/") {
		return true
	}
	return false
}

// isAuditPackageOwnFile lets the audit package's source contain
// references to its own table without tripping the lint. The package
// is the only legitimate site of those references because it owns
// the INSERT statement; the test still catches a future drift inside
// the package by inspection during code review.
func isAuditPackageOwnFile(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return strings.HasPrefix(rel, "server/identity/internal/audit/")
}
