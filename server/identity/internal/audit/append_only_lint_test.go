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

// forbiddenAuditSQL matches an UPDATE or DELETE FROM statement against audit_events anywhere in a Go source file. Word boundaries keep
// the regex from matching unrelated identifiers (e.g., `updateAuditEvents` as a Go function name) and case-insensitive so SQL casing
// variations all trip the gate.
var forbiddenAuditSQL = regexp.MustCompile(
	`(?i)\b(update\s+audit_events|delete\s+from\s+audit_events)\b`)

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
//     server/identity/bootstrap/schema.go and the regex deliberately
//     does not match CREATE.
//
// The audit package itself is NOT excluded (per PR #120 review,
// Copilot + CodeRabbit): the regex is UPDATE/DELETE-specific so the
// legitimate INSERT in mysql.go does not trip, and policing the
// package is the point — that's the most likely regression site.
//
// A future archival job (wave-2 retention) would land in its own
// package and need an explicit exception added to the allowed-list,
// at which point the rule's intent is the discussion the change
// invites — exactly the code-review signal the spec wanted.
// spec:server-identity-audit-log/append-only-persistence/no-code-path-updates-an-audit-row
func TestAuditEventsAppendOnly(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	violations, err := scanForForbiddenSQL(root)
	require.NoError(t, err)
	assert.Empty(t, violations,
		"audit_events is append-only; UPDATE/DELETE found in production source. "+
			"If this is a wave-2 archival job, add an explicit exception in this lint and "+
			"document the package-level rationale.")
}

// scanForForbiddenSQL walks the Go source tree under root and returns every "<path>: <match>" string for files containing the
// forbidden regex. Pulled out of TestAuditEventsAppendOnly so the parent test's cognitive complexity stays under Sonar's S3776
// threshold (the walk callback's branching dominated complexity at CC=17).
func scanForForbiddenSQL(root string) ([]string, error) {
	var violations []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if shouldSkipDir(path, root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !shouldScanFile(path) {
			return nil
		}
		match, err := fileForbiddenMatch(path)
		if err != nil {
			return err
		}
		if match != "" {
			violations = append(violations, path+": "+match)
		}
		return nil
	})
	return violations, err
}

// shouldScanFile reports whether path is a Go production source file the lint should inspect. Test files are exempt (fixtures may
// legitimately mutate audit_events); non-Go files are skipped.
func shouldScanFile(path string) bool {
	if !strings.HasSuffix(path, ".go") {
		return false
	}
	if strings.HasSuffix(path, "_test.go") {
		return false
	}
	return true
}

// fileForbiddenMatch returns the matched substring if path's content
// trips the forbidden regex, or "" if it does not. Read-only.
func fileForbiddenMatch(path string) (string, error) {
	// path is fully under the repo root (we walk from there) and the
	// lint is read-only — no file-inclusion risk.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return "", err
	}
	if loc := forbiddenAuditSQL.FindIndex(data); loc != nil {
		return string(data[loc[0]:loc[1]]), nil
	}
	return "", nil
}

// repoRoot derives the repository root from this source file's path
// at compile time. runtime.Caller is robust across test runners
// (working dir may be the package dir or the repo root depending on
// how the test is invoked) and OS path separators (filepath.Join
// normalises).
//
// Per PR #120 review (CodeRabbit), the derived path is verified to
// contain a go.mod file before being returned. Without the guard,
// `-trimpath` builds (used in some CI release pipelines) yield a
// module-relative path whose four-up resolution lands in the test
// runner's working directory, and the lint silently scans an empty
// tree.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must report this file's path")
	// This file lives at server/identity/internal/audit/<name>_test.go;
	// the repo root is four directories up.
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	_, err := os.Stat(filepath.Join(root, "go.mod"))
	require.NoErrorf(t, err,
		"derived repo root %q must contain go.mod; "+
			"check directory depth or -trimpath interactions",
		root)
	return root
}

// shouldSkipDir reports whether walking under dir would scan content the lint should not police. Non-Go directories and third-party
// trees are excluded so a transitive dependency mentioning an "audit_events" column in its own SQL doesn't fail the build.
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
	return strings.Contains(filepath.ToSlash(rel), "/node_modules/")
}
