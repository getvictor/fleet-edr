// Package arch holds the architecture-lint test that runs as part of every
// `go test ./...` invocation. The test loads arch-go.yml at the repo root,
// walks the module's package graph, and fails on any rule violation.
//
// See docs/adr/0004-modular-monolith-bounded-contexts.md and
// claude/modular-monolith/phase1.md for the rationale + per-phase rule
// roll-out plan.
package arch_test

import (
	"strings"
	"testing"

	archapi "github.com/arch-go/arch-go/api"
	"github.com/arch-go/arch-go/api/configuration"
)

const (
	// configPath is relative to this test file's directory; the file lives
	// at test/arch/, the config at the repo root.
	configPath = "../../arch-go.yml"
	// modulePath is the Go module path declared in go.mod. arch-go discovers
	// packages by walking everything under it.
	modulePath = "github.com/fleetdm/edr"
)

func TestArchitecture(t *testing.T) {
	cfg, err := configuration.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load %s: %v", configPath, err)
	}
	if cfg == nil {
		t.Fatalf("loaded config is nil")
	}

	moduleInfo := configuration.Load(modulePath)

	result := archapi.CheckArchitecture(moduleInfo, *cfg)
	if result == nil {
		t.Fatalf("arch-go returned nil result")
	}
	if !result.Pass {
		t.Fatalf("architecture violations:\n%s", summarize(result))
	}
}

// summarize formats the failing rules into a readable error message. arch-go's
// Result type carries per-rule details on .DependenciesRuleResult,
// .ContentsRuleResult, etc.; we surface only the dependency failures since
// that's the only rule family in use for now.
func summarize(r *archapi.Result) string {
	var b strings.Builder
	if r.DependenciesRuleResult != nil && !r.DependenciesRuleResult.Passes {
		for _, dr := range r.DependenciesRuleResult.Results {
			if dr.Passes {
				continue
			}
			b.WriteString("dependency rule: ")
			b.WriteString(dr.Description)
			b.WriteString("\n")
			for _, vr := range dr.Verifications {
				if vr.Passes {
					continue
				}
				b.WriteString("  package ")
				b.WriteString(vr.Package)
				b.WriteString("\n")
				for _, d := range vr.Details {
					b.WriteString("    ")
					b.WriteString(d)
					b.WriteString("\n")
				}
			}
		}
	}
	if b.Len() == 0 {
		b.WriteString("(no detail; check arch-go output)")
	}
	return b.String()
}
