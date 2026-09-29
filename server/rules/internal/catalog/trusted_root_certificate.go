package catalog

import (
	"context"
	"fmt"
	"sync"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigma"
)

// TrustedRootCertificate fires when `security` is asked to trust a certificate: `add-trusted-cert` or `trust-settings-import`,
// which write the trust settings macOS consults for every TLS connection and code signature it evaluates (T1553.004). A root an
// attacker controls lets them intercept the host's TLS traffic, or have their own signatures pass.
//
// Keyed on the exec, which the sensor already reports with its argv (issue #1167). A trust setting written through the Security
// framework by another program runs no `security` exec and is not seen; a configuration profile installed by MDM is the managed
// way to deploy a root and is not reported either.
type TrustedRootCertificate struct{}

func (r *TrustedRootCertificate) ID() string { return "trusted_root_certificate" }

// SupportedExclusionMatchTypes is none: the process is always Apple's `security` and its parent is usually a shell, so neither
// names what an operator would trust. A host that deploys roots this way runs the rule in monitor.
func (r *TrustedRootCertificate) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }

// DisplayName is the canonical human-readable name reused by Doc().Title and the finding (issue #519).
func (r *TrustedRootCertificate) DisplayName() string {
	return "Certificate trusted from the command line"
}

// Techniques returns T1553.004 (Subvert Trust Controls: Install Root Certificate).
func (r *TrustedRootCertificate) Techniques() []string { return []string{"T1553.004"} }

// Doc surfaces the operator-facing description in /api/rules and the generated docs/detection-rules.md.
func (r *TrustedRootCertificate) Doc() api.Documentation {
	return api.Documentation{
		Title:   r.DisplayName(),
		Summary: "Flags `security add-trusted-cert` or `security trust-settings-import`, which make macOS trust a certificate.",
		Description: "Detects a root certificate being installed on macOS (T1553.004). A certificate the host trusts as a root lets " +
			"whoever holds its key intercept the host's TLS connections, or sign code the host will accept.\n\n" +
			"Fires on an invocation of `/usr/bin/security` whose subcommand is `add-trusted-cert` or `trust-settings-import`, both " +
			"of which write trust settings. `add-certificates`, which adds a certificate without trusting it, is left out, as are " +
			"a `-h`, which prints help, a result type of `deny` or `unspecified`, which records a certificate as not trusted, and " +
			"`-o`, which writes the trust settings to a file instead of the host.",
		Severity:   api.SeverityHigh,
		EventTypes: []string{"exec"},
		FalsePositives: []string{
			"An administrator or an IT script deploying an internal root by hand. Prefer a configuration profile pushed by MDM, " +
				"which is not reported; where a script is how it is done, set this rule to monitor on the hosts it runs on.",
		},
		Limitations: []string{
			"A trust setting written through the Security framework by a program of its own runs no `security` exec and is not " +
				"reported.",
			"A certificate installed by a configuration profile is not reported, whoever pushed the profile.",
		},
	}
}

// trustedRootDetection is the rule's logic, compiled from the detection block in its pack file.
var trustedRootDetection = sync.OnceValue(func() *sigma.Rule { return detectionFor("trusted_root_certificate") })

func (r *TrustedRootCertificate) Evaluate(ctx context.Context, events []api.Event, s api.GraphReader) ([]api.Finding, error) {
	return r.EvaluateScoped(ctx, &api.BatchScope{}, events, s)
}

// CountsMaterializationAbandons declares that every abandon this rule makes is recorded, through the shared Sigma view, so its
// zero is a measurement.
func (r *TrustedRootCertificate) CountsMaterializationAbandons() {}

// EvaluateScoped implements api.ScopedRule.
func (r *TrustedRootCertificate) EvaluateScoped(
	ctx context.Context, scope *api.BatchScope, events []api.Event, s api.GraphReader,
) ([]api.Finding, error) {
	return evalEachScopedEvent(ctx, scope, events, s, r.evalEvent)
}

func (r *TrustedRootCertificate) evalEvent(
	ctx context.Context, scope *api.BatchScope, evt api.Event, s api.GraphReader,
) (*api.Finding, error) {
	if evt.EventType != "exec" {
		return nil, nil
	}
	view := sigmaEvent(ctx, scope, evt, s)
	if view == nil {
		return nil, nil
	}
	se := view.Event
	if !trustedRootDetection().Matches(se) {
		view.noteUnmatched(scope, r.ID())
		return nil, nil
	}
	proc, err := view.subjectOrAbandon(scope, r.ID())
	if err != nil || proc == nil {
		return nil, err
	}
	// The subcommand the detection matched on, read back from the same computed field, so the alert names what fired. An import
	// applies whatever the file holds, deny entries included, so it is reported as a change to trust rather than as a trusted root.
	sub := firstField(se, "Subcommand")
	effect := "makes the host trust a certificate"
	if sub == "trust-settings-import" {
		effect = "imports certificate trust settings, which can make the host trust a certificate"
	}
	return &api.Finding{
		HostID:      evt.HostID,
		RuleID:      r.ID(),
		Severity:    api.SeverityHigh,
		Title:       r.DisplayName(),
		Description: fmt.Sprintf("%s invoked with %q: %s (MITRE T1553.004)", firstField(se, "Image"), sub, effect),
		ProcessID:   proc.ID,
		EventIDs:    []string{evt.EventID},
	}, nil
}
