package catalog

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fleetdm/edr/internal/installerscript"
	"github.com/fleetdm/edr/server/rules/api"
)

// InstallerUnsignedPackage fires when an installer script runs from a package that is unsigned, or whose signature macOS does not
// trust (T1546.016). A package's preinstall and postinstall run as root, so an unsigned package that a user is talked into opening
// runs its payload with full privilege and leaves the persistence it likes. Vendors sign their packages, and Gatekeeper refuses an
// unsigned one unless the user overrides it, which is what makes the unsigned case the signal.
//
// It reads the package signature the agent attaches to an installer script's exec (issue #1161). The agent attaches it only when
// the exec's parent is PackageKit's package_script_service, so its presence already says this is an installer script, and the rule
// needs no ancestor walk. An agent from before that attaches nothing, and the rule never fires for it.
type InstallerUnsignedPackage struct {
	// Exclusions is the per-host false-positive resolver, consulted for the package's path. Nil excludes nothing.
	Exclusions api.ExclusionResolver
}

func (r *InstallerUnsignedPackage) ID() string { return "installer_unsigned_package" }

// AlgorithmName names the evaluator that decides this rule, for the exported rule file.
func (r *InstallerUnsignedPackage) AlgorithmName() string { return "installer_package_signature" }

// SupportedExclusionMatchTypes is the package's path. An unsigned package names no team, so there is nothing else to trust it by.
func (r *InstallerUnsignedPackage) SupportedExclusionMatchTypes() []api.ExclusionMatchType {
	return []api.ExclusionMatchType{api.ExclusionMatchPathGlob}
}

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *InstallerUnsignedPackage) DisplayName() string { return "Unsigned installer package" }

// Techniques returns T1546.016 (Event Triggered Execution: Installer Packages).
func (r *InstallerUnsignedPackage) Techniques() []string { return []string{"T1546.016"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *InstallerUnsignedPackage) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags an installer script run from a package that is unsigned or whose signature macOS does not trust.",
		Description: "Detects malicious installer packages on macOS (T1546.016): a package's preinstall and postinstall scripts run " +
			"as root, so a package a user is talked into opening can run anything with full privilege.\n\n" +
			"Keyed on the package's signature, which the agent reads when macOS's installer runs one of its scripts. Vendors sign " +
			"their packages, and macOS refuses an unsigned one unless the user overrides it, so an unsigned or untrusted package " +
			"running a script is rare. One alert is raised per package, however many scripts it runs.\n\n" +
			"`suspicious_exec` also reports each of a package's scripts, signed or not, and is excluded by the team that signed " +
			"the package. This rule is what still reports a package that names no team to exclude.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"An in-house package that was never signed. Prefer signing it with a Developer ID Installer certificate; failing " +
				"that, a path-glob exclusion on where it is installed from, with an expiry, since anyone who can write that path " +
				"inherits the exclusion.",
		},
		Limitations: []string{
			"A package with no scripts runs nothing at install time and is not reported, although its files still land.",
			"A package whose file is gone by the time its script is read (one that deletes itself, say) cannot be classified and " +
				"is not reported. `suspicious_exec` still reports its scripts.",
			"A package signed by a certificate macOS has revoked or does not trust is reported alongside an unsigned one; the " +
				"alert does not tell them apart.",
		},
	}
}

func (r *InstallerUnsignedPackage) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// CountsMaterializationAbandons declares that every abandon this rule makes is recorded, so its zero is a measurement.
func (r *InstallerUnsignedPackage) CountsMaterializationAbandons() {}

// EvaluateScoped implements api.ScopedRule.
func (r *InstallerUnsignedPackage) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachScopedEvent(ctx, scope, events, s, r.evalExec)
}

func (r *InstallerUnsignedPackage) evalExec(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	if evt.EventType != "exec" {
		return nil, nil
	}
	var p execPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil || p.PackageSigning == nil || p.PackageSigning.Signed || p.PID <= 0 {
		return nil, nil
	}
	// The agent found the package by this same function before it read the signature, so the pair is always present here.
	script, pkg := installerscript.Locate(p.Args)
	if r.Exclusions != nil && r.Exclusions.Excluded(r.ID(), api.ExclusionMatchPathGlob, pkg, evt.HostID) {
		return nil, nil
	}
	proc, err := resolveSubjectProcess(ctx, s, evt, p.PID)
	if err != nil {
		return nil, err
	}
	if proc == nil {
		// Past the materialization grace: recorded, so a script the rule never got to judge is not read as one it judged benign.
		scope.RecordMaterializationAbandoned(r.ID(), p.PID)
		return nil, nil
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("Installer script %s ran from unsigned or untrusted package %s", script, pkg),
		ProcessID:   proc.ID,
		// One alert per package: its preinstall and postinstall are separate execs, and so is each script of a package it contains.
		Subject:  pathSubject("installerpkg", pkg),
		EventIDs: []string{evt.EventID},
	}, nil
}
