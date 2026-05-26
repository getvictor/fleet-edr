package main

import (
	"path/filepath"
	"strings"
)

// Layer is the test-pyramid rung defined in docs/testing-strategy.md. The integer values are stable: report column ordering,
// the gap output, and the --by-layer flag all assume L0..L6 ordering. LayerOther is sentinel -1 for markers on enforcement
// surfaces that are not themselves a test layer (workflow YAML, packaging shell scripts, etc.); the report renders an
// `Other` column for these only when at least one scenario has such a marker so the standard matrix stays compact.
//
// L5 (System / VM) is intentionally not auto-detected: there is no path prefix that uniquely identifies an L5 test in this
// repo (the VM driver lives under `scripts/uat/` and runs scenarios out of `test/efficacy/corpus/.../attack.sh`). Adding
// an L5 marker today requires a Go test or similar surface inside `test/integration/` that explicitly drives the VM. If a
// future L5 harness lands with its own path prefix, add the case to ClassifyLayer.
type Layer int

const (
	LayerOther         Layer = -1
	LayerUnit          Layer = 0
	LayerPerContext    Layer = 1
	LayerCrossContext  Layer = 2
	LayerHeadlessAgent Layer = 3
	LayerBrowserE2E    Layer = 4
	LayerSystemVM      Layer = 5
	LayerEfficacy      Layer = 6
)

// allTestLayers is the ordered set of L0..L6 columns the report renders by default. LayerOther is excluded; the report
// renderer adds it on demand.
var allTestLayers = [...]Layer{
	LayerUnit, LayerPerContext, LayerCrossContext, LayerHeadlessAgent,
	LayerBrowserE2E, LayerSystemVM, LayerEfficacy,
}

// Label is the short header used in report columns and the gap output (L0..L6 / Other).
func (l Layer) Label() string {
	switch l {
	case LayerUnit:
		return "L0"
	case LayerPerContext:
		return "L1"
	case LayerCrossContext:
		return "L2"
	case LayerHeadlessAgent:
		return "L3"
	case LayerBrowserE2E:
		return "L4"
	case LayerSystemVM:
		return "L5"
	case LayerEfficacy:
		return "L6"
	case LayerOther:
		return "Other"
	default:
		return "Other"
	}
}

// ClassifyLayer maps a forward-slash repo-relative path to a Layer per the heuristics in issue #233 + docs/testing-strategy.md.
// The check order is deepest-prefix-first because `test/integration/agentserver/` is a sub-prefix of `test/integration/` and
// would otherwise classify as L2. Inputs are normalised to forward slashes; callers that pass an OS-native path do not need
// to convert.
func ClassifyLayer(path string) Layer {
	p := filepath.ToSlash(path)
	switch {
	case strings.HasPrefix(p, "test/efficacy/"):
		return LayerEfficacy
	case strings.HasPrefix(p, "test/e2e/tests/"):
		return LayerBrowserE2E
	case strings.HasPrefix(p, "test/integration/agentserver/"):
		return LayerHeadlessAgent
	case strings.HasPrefix(p, "test/integration/"):
		return LayerCrossContext
	case isPerContextTestPath(p):
		return LayerPerContext
	case isUnitTestPath(p):
		return LayerUnit
	default:
		return LayerOther
	}
}

// isPerContextTestPath matches `server/<context>/internal/tests/...` (the L1 home documented in docs/testing-strategy.md).
// Per-context tests at any deeper path under `internal/tests/` (e.g. `server/identity/internal/tests/journeys/foo_test.go`)
// also count as L1; the prefix check has no depth cap.
func isPerContextTestPath(p string) bool {
	if !strings.HasPrefix(p, "server/") {
		return false
	}
	parts := strings.Split(p, "/")
	// server / <context> / internal / tests / ...
	return len(parts) >= 5 && parts[2] == "internal" && parts[3] == "tests"
}

// isUnitTestPath catches anything that looks like a unit test: Go `_test.go`, vitest `.test.ts(x)`, and Swift sources living
// under a `Tests/` directory (the SwiftPM convention used in extension/edr/Tests/). The Swift case is a containment check
// rather than a prefix because the package root is `extension/edr/Tests/...` but a future repo layout could place tests
// elsewhere. Markers in non-test Swift sources fall through to LayerOther.
func isUnitTestPath(p string) bool {
	switch {
	case strings.HasSuffix(p, "_test.go"):
		return true
	case strings.HasSuffix(p, ".test.ts"), strings.HasSuffix(p, ".test.tsx"):
		return true
	case strings.HasSuffix(p, ".swift") && strings.Contains(p, "/Tests/"):
		return true
	default:
		return false
	}
}
