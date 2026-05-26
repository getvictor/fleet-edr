package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestClassifyLayer pins the path-prefix rules in issue #233. Each case names the layer it exercises so a future reader
// debugging an "unexpected layer" finding goes straight to the row, not the function. The deepest-prefix-first ordering
// inside ClassifyLayer is what makes `test/integration/agentserver/...` resolve to L3 rather than L2; the two rows that
// share that prefix are kept adjacent so a reordering bug is immediately visible.
func TestClassifyLayer(t *testing.T) {
	cases := []struct {
		name string
		path string
		want Layer
	}{
		{"L0 go unit test under package root", "agent/queue/queue_test.go", LayerUnit},
		{"L0 go unit test under internal package", "internal/observability/observability_test.go", LayerUnit},
		{"L0 vitest .test.ts", "ui/src/auth.test.ts", LayerUnit},
		{"L0 vitest .test.tsx", "ui/src/components/Login.test.tsx", LayerUnit},
		{"L0 swift XCTest under SwiftPM Tests root", "extension/edr/Tests/EDRExtensionLogicTests/DNSParserTests.swift", LayerUnit},

		{"L1 per-context test (response context)", "server/response/internal/tests/handler_test.go", LayerPerContext},
		{"L1 per-context test nested directory", "server/identity/internal/tests/journeys/login_test.go", LayerPerContext},
		{"server unit test is L0, not L1 (no internal/tests prefix)", "server/metrics/metrics_test.go", LayerUnit},

		{"L2 cross-context test", "test/integration/full_path_test.go", LayerCrossContext},
		{"L2 cross-context test deeper", "test/integration/authz_journey_test.go", LayerCrossContext},

		{"L3 headless agent integration", "test/integration/agentserver/agentserver_test.go", LayerHeadlessAgent},

		{"L4 playwright auth spec", "test/e2e/tests/auth/oidc-login.spec.ts", LayerBrowserE2E},
		{"L4 playwright qa spec", "test/e2e/tests/qa/host-list-and-process-tree.spec.ts", LayerBrowserE2E},

		{"L6 efficacy harness", "test/efficacy/efficacy_test.go", LayerEfficacy},
		{"L6 efficacy corpus yaml", "test/efficacy/corpus/T1059/scenario.yaml", LayerEfficacy},

		{"Other: release-packaging workflow yaml", ".github/workflows/release.yml", LayerOther},
		{"Other: release-packaging shell script", "packaging/pkg/build.sh", LayerOther},
		{"Other: production Go source (no _test.go suffix)", "agent/uploader/uploader.go", LayerOther},
		{"Other: production Swift source (no /Tests/ in path)", "extension/edr/main.swift", LayerOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ClassifyLayer(tc.path), "ClassifyLayer(%q)", tc.path)
		})
	}
}

// TestLayerLabel pins the column-header strings the report renderer uses. The Label() output is part of the report contract;
// if a future PR renames any of these strings, the Markdown matrix shape changes and downstream tooling (PR summaries, dash-
// boards that grep `L0` etc.) breaks. Treat any change here as a contract change, not an implementation detail.
func TestLayerLabel(t *testing.T) {
	cases := []struct {
		l    Layer
		want string
	}{
		{LayerUnit, "L0"},
		{LayerPerContext, "L1"},
		{LayerCrossContext, "L2"},
		{LayerHeadlessAgent, "L3"},
		{LayerBrowserE2E, "L4"},
		{LayerSystemVM, "L5"},
		{LayerEfficacy, "L6"},
		{LayerOther, "Other"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.l.Label())
		})
	}
}
