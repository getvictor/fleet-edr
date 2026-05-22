package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Marker is one reference to a spec ID found in the codebase. SourcePath is normalised to a forward-slash repo-relative
// path (e.g. `test/scale/scale_test.go`) so report output is the same whether the caller invoked `spectrace check` with
// `--root=.` or an absolute path.
type Marker struct {
	ID         string
	SourcePath string
	SourceLine int
}

// markerRE captures candidate IDs after the literal `spec:` prefix. The capture allows uppercase, underscores, and
// arbitrary segment shapes so malformed markers (e.g. `spec:Wrong-Case/foo`) reach the downstream validation step rather
// than being silently dropped by an over-strict shape filter. The canonical-ID validation in runCheck reports any
// non-canonical capture as an invalid reference. The leading non-word boundary stops it from matching the middle of an
// identifier or path; we anchor on the literal "spec:" prefix.
var markerRE = regexp.MustCompile(`(?:\W|^)spec:([A-Za-z0-9][A-Za-z0-9_/-]*)`)

// swiftMarkerRE matches the Swift XCTest form `test_spec_<underscore_id>`. Underscores in the captured ID are ambiguous
// (`-` and `/` both map to `_` per docs/testing-strategy.md), so resolveSwift reconciles against the known canonical-ID set.
var swiftMarkerRE = regexp.MustCompile(`\btest_spec_([a-z0-9_]+)\b`)

// ScanMarkers walks rootDir and returns every marker reference found in Go / TS / TSX / Swift sources. Returns markers in
// file-encounter order; the caller sorts as needed.
//
// `tools/spectrace` is excluded from the walk because the linter's own test fixtures construct example marker strings; if
// counted, they would inflate the coverage number and emit false-positive invalid-reference warnings against the linter's
// own corpus.
func ScanMarkers(rootDir string, canonicalIDs map[string]struct{}) ([]Marker, error) {
	swiftIndex := buildSwiftIndex(canonicalIDs)
	var markers []Marker
	walker := newMarkerWalker(rootDir, canonicalIDs, swiftIndex)
	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		fileMarkers, action, err := walker.visit(path, d)
		if err != nil {
			return err
		}
		markers = append(markers, fileMarkers...)
		return action
	})
	return markers, err
}

// markerWalker bundles the constant state (rootDir, skiplist, indexes) that filepath.WalkDir's visitor closure would
// otherwise close over. Splitting the per-entry decision out as `visit` keeps the ScanMarkers function under the cognitive
// complexity budget the lint config enforces (go:S3776 fires at 15+; the previous shape was 20).
type markerWalker struct {
	rootDir      string
	skipDirs     map[string]struct{}
	skipRelPaths map[string]struct{}
	canonicalIDs map[string]struct{}
	swiftIndex   map[string][]string
}

func newMarkerWalker(rootDir string, canonicalIDs map[string]struct{}, swiftIndex map[string][]string) *markerWalker {
	return &markerWalker{
		rootDir: rootDir,
		skipDirs: map[string]struct{}{
			".git":         {},
			"node_modules": {},
			"vendor":       {},
			"tmp":          {},
			"dist":         {},
			".build":       {}, // SwiftPM
			"build":        {},
		},
		skipRelPaths: map[string]struct{}{
			filepath.Join("tools", "spectrace"): {},
		},
		canonicalIDs: canonicalIDs,
		swiftIndex:   swiftIndex,
	}
}

// visit returns the markers (if any) found in `path`, and an error-or-action value to return to filepath.WalkDir. The
// triple-return shape lets the caller stay a one-liner inside the WalkDir closure while pushing the per-entry decisions
// (skip-dir, skip-file, scan) into this method.
func (w *markerWalker) visit(path string, d os.DirEntry) ([]Marker, error, error) {
	if d.IsDir() {
		if _, skip := w.skipDirs[d.Name()]; skip {
			return nil, nil, filepath.SkipDir
		}
		if rel, relErr := filepath.Rel(w.rootDir, path); relErr == nil {
			if _, skip := w.skipRelPaths[rel]; skip {
				return nil, nil, filepath.SkipDir
			}
		}
		return nil, nil, nil
	}
	ext := strings.ToLower(filepath.Ext(d.Name()))
	switch ext {
	case ".go", ".ts", ".tsx", ".swift":
	default:
		return nil, nil, nil
	}
	relPath, err := filepath.Rel(w.rootDir, path)
	if err != nil {
		relPath = path
	}
	relPath = filepath.ToSlash(relPath)
	f, err := os.Open(path) //nolint:gosec // path comes from filepath.WalkDir under rootDir
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err), nil
	}
	defer f.Close()
	markers, err := scanFile(f, relPath, ext == ".swift", w.canonicalIDs, w.swiftIndex)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err), nil
	}
	return markers, nil, nil
}

// scanFile reads r line by line and emits markers it sees. The isSwift branch also resolves the ambiguous underscored Swift
// form against the precomputed swiftIndex so the marker's reported ID is the slashed canonical form regardless of source
// dialect. Swift identifiers that match multiple canonical IDs are reported as ambiguous (prefix `swift-ambiguous:`) and
// flow into the invalid-reference bucket so a contributor must rename to disambiguate.
func scanFile(r io.Reader, path string, isSwift bool, canonicalIDs map[string]struct{},
	swiftIndex map[string][]string,
) ([]Marker, error) {
	var out []Marker
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, m := range markerRE.FindAllStringSubmatch(line, -1) {
			out = append(out, Marker{ID: m[1], SourcePath: path, SourceLine: lineNo})
		}
		if isSwift {
			for _, m := range swiftMarkerRE.FindAllStringSubmatch(line, -1) {
				out = append(out, resolveSwiftMarker(m[1], path, lineNo, swiftIndex))
			}
		}
		_ = canonicalIDs // unused; reserved for future per-line validation hooks
	}
	return out, scanner.Err()
}

// resolveSwiftMarker disambiguates a Swift identifier body against the precomputed swiftIndex. Three outcomes:
//
//	exactly one matching canonical ID → emit the canonical (slashed) form so the marker counts as coverage.
//	zero matches                        → emit `swift:<body>` so check reports it as an invalid reference.
//	two or more matches                 → emit `swift-ambiguous:<body>` so check reports it as an invalid reference. This
//	                                      is the failure shape when two canonical IDs share a Swift form (e.g. `foo-bar`
//	                                      vs `foo/bar`); a non-deterministic "first match wins" would attribute coverage
//	                                      to the wrong scenario across runs.
func resolveSwiftMarker(body, path string, lineNo int, swiftIndex map[string][]string) Marker {
	matches := swiftIndex[body]
	switch len(matches) {
	case 1:
		return Marker{ID: matches[0], SourcePath: path, SourceLine: lineNo}
	case 0:
		return Marker{ID: "swift:" + body, SourcePath: path, SourceLine: lineNo}
	default:
		return Marker{ID: "swift-ambiguous:" + body, SourcePath: path, SourceLine: lineNo}
	}
}

// buildSwiftIndex maps each Swift dialect form (slashes + dashes collapsed to underscores) back to every canonical ID that
// produces it. Built once per ScanMarkers call so a marker scan over thousands of files does not re-iterate the canonical
// set per Swift identifier.
func buildSwiftIndex(canonicalIDs map[string]struct{}) map[string][]string {
	out := make(map[string][]string, len(canonicalIDs))
	for id := range canonicalIDs {
		sf := swiftFormOf(id)
		out[sf] = append(out[sf], id)
	}
	return out
}

func swiftFormOf(id string) string {
	return strings.NewReplacer("/", "_", "-", "_").Replace(id)
}
