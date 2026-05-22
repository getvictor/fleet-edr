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

// Marker is one reference to a spec ID found in the codebase.
type Marker struct {
	ID         string // canonical ID (slashed form) the marker resolves to
	SourcePath string // repo-relative
	SourceLine int    // 1-based
}

// markerRE matches the `spec:<id>` form (Go/TS subtest names, comments, and Playwright titles) where <id> is at least three
// slash-separated segments of lowercase alphanumerics + dashes. The leading non-word boundary stops it from matching the
// middle of an identifier or path; we anchor on the literal "spec:" prefix.
var markerRE = regexp.MustCompile(`(?:\W|^)spec:([a-z0-9][a-z0-9-]*(?:/[a-z0-9-]+){2,})`)

// swiftMarkerRE matches the Swift XCTest form `test_spec_<underscore_id>`. Underscores in the captured ID are ambiguous
// (`-` and `/` both map to `_` per docs/testing-strategy.md), so resolveSwift reconciles against the known canonical-ID set.
var swiftMarkerRE = regexp.MustCompile(`\btest_spec_([a-z0-9_]+)\b`)

// ScanMarkers walks rootDir and returns every marker reference found in Go / TS / TSX / Swift sources. Returns markers in
// file-encounter order; the caller sorts as needed. The dirSkipList prunes vendored / generated trees so the walk runs in
// milliseconds against this repo.
//
// `tools/spectrace` is excluded from the walk: the linter's own test fixtures construct example spec markers as strings, and
// counting those as real codebase references would inflate coverage and emit false-positive invalid-reference warnings on
// the linter's own corpus. A future report of `tools/spectrace` coverage is irrelevant by construction — this binary is
// not the system under test.
func ScanMarkers(rootDir string, canonicalIDs map[string]struct{}) ([]Marker, error) {
	var markers []Marker
	skipDirs := map[string]struct{}{
		".git":         {},
		"node_modules": {},
		"vendor":       {},
		"tmp":          {},
		"dist":         {},
		".build":       {}, // SwiftPM
		"build":        {},
	}
	skipRelPaths := map[string]struct{}{
		filepath.Join("tools", "spectrace"): {},
	}
	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			rel, relErr := filepath.Rel(rootDir, path)
			if relErr == nil {
				if _, skip := skipRelPaths[rel]; skip {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".go", ".ts", ".tsx", ".swift":
		default:
			return nil
		}
		f, err := os.Open(path) //nolint:gosec // path comes from filepath.WalkDir under rootDir
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		fileMarkers, err := scanFile(f, path, ext == ".swift", canonicalIDs)
		if err != nil {
			return fmt.Errorf("scan %s: %w", path, err)
		}
		markers = append(markers, fileMarkers...)
		return nil
	})
	return markers, err
}

// scanFile reads r line by line and emits markers it sees. The isSwift branch also resolves the ambiguous underscored Swift
// form against the canonical-ID set so the marker's reported ID is the slashed canonical form regardless of source dialect.
func scanFile(r io.Reader, path string, isSwift bool, canonicalIDs map[string]struct{}) ([]Marker, error) {
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
				canonical, ok := resolveSwift(m[1], canonicalIDs)
				if !ok {
					// Swift identifier doesn't match any known canonical ID. Emit it as-is with an `swift:` prefix so the
					// check pass can flag it as an invalid reference; that's better than silently dropping a typo.
					out = append(out, Marker{ID: "swift:" + m[1], SourcePath: path, SourceLine: lineNo})
					continue
				}
				out = append(out, Marker{ID: canonical, SourcePath: path, SourceLine: lineNo})
			}
		}
	}
	return out, scanner.Err()
}

// resolveSwift takes the underscored body of a `test_spec_<...>` identifier and tries to find a canonical ID whose Swift form
// matches. The Swift form is computed by replacing `/` and `-` in the canonical ID with `_`. Returns (canonicalID, true) on
// match or ("", false) when no canonical ID matches.
func resolveSwift(swiftID string, canonicalIDs map[string]struct{}) (string, bool) {
	for id := range canonicalIDs {
		if swiftFormOf(id) == swiftID {
			return id, true
		}
	}
	return "", false
}

func swiftFormOf(id string) string {
	return strings.NewReplacer("/", "_", "-", "_").Replace(id)
}
