// Package arch_test holds the architecture-lint test that runs as part of
// every `go test ./...` invocation. The test loads arch-go.yml at the repo
// root, walks the module's package graph, and fails on any rule violation.
//
// See docs/adr/0004-modular-monolith-bounded-contexts.md for the rationale
// and per-phase rule roll-out plan.
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

// summarize formats the failing rules into a readable error message. arch-go's Result type carries per-rule details on
// .DependenciesRuleResult, .ContentsRuleResult, etc.; we surface only the dependency failures since that's the only rule family in use
// for now.
func summarize(r *archapi.Result) string {
	var b strings.Builder
	summarizeDependencies(&b, r)
	if b.Len() == 0 {
		b.WriteString("(no detail; check arch-go output)")
	}
	return b.String()
}

// summarizeDependencies walks the dependency-rule sub-results and renders
// each failing verification as one line per offending package + one line
// per offending import detail. Split out of summarize so each function
// stays under the cognitive-complexity gate.
//
// arch-go's Verification type lives in an internal package, so the
// nested writeRuleFailure / writeVerificationFailure helpers below take
// primitives (description, package name, details slice) instead of the
// typed value, crossing the typed boundary into primitives once at
// the loop site, then the helpers don't pull arch-go internals in.
func summarizeDependencies(b *strings.Builder, r *archapi.Result) {
	if r.DependenciesRuleResult == nil || r.DependenciesRuleResult.Passes {
		return
	}
	for _, dr := range r.DependenciesRuleResult.Results {
		if dr.Passes {
			continue
		}
		b.WriteString("dependency rule: ")
		b.WriteString(dr.Description)
		b.WriteString("\n")
		for _, vr := range dr.Verifications {
			if !vr.Passes {
				writeVerificationFailure(b, vr.Package, vr.Details)
			}
		}
	}
}

func writeVerificationFailure(b *strings.Builder, pkg string, details []string) {
	b.WriteString("  package ")
	b.WriteString(pkg)
	b.WriteString("\n")
	for _, d := range details {
		b.WriteString("    ")
		b.WriteString(d)
		b.WriteString("\n")
	}
}
