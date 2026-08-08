// Package selfheal restores network extension capture providers that have stopped.
//
// A stopped provider takes its telemetry stream with it, and before this the host stayed blind until a human noticed the
// health alert and ran the host app's activate by hand (issue #632). Two triggers are on record for the same end state: an
// agent pkg upgrade, and a disable/re-enable of the network extension from System Settings. Install-time activation is not
// the gap, because the pkg postinstall has re-run the activation LaunchAgent on upgrade since #357 and that code was in the
// pkg that failed. So remediation here keys on the OUTCOME the extension reports ("this provider is not capturing") rather
// than on any inference about the cause, which is what lets one mechanism cover triggers nobody has enumerated yet.
//
// The decision logic is deliberately pure and the platform call is injected, because the interesting behaviour is the
// policy: what counts as eligible, when to wait, when to give up. That is all testable without touching the host app.
package selfheal

import "sort"

// ProviderStopped is the state the network extension reports for a provider that stopped through a fault. It mirrors the
// wire value defined by the extension's ProviderLiveness (issue #649); a provider the operator deliberately disabled is
// ABSENT from the map instead, which is what makes remediation safe to run without asking.
const ProviderStopped = "stopped"

// subcommand maps a provider wire identifier to the host-app subcommand that re-enables it. A provider missing from this
// table is reported but not remediable, which is the honest default for one this build does not know how to restore: it
// still shows up as unhealthy, it just is not acted on.
var subcommand = map[string]string{
	"content_filter": "enable-filter",
	"dns_proxy":      "enable-dns-proxy",
}

// Remediable returns the providers in a liveness report that are both stopped and known to be restorable, sorted so the
// remediation order (and the resulting logs) are deterministic.
//
// The absence rule is the whole safety story. #649 reports an operator-disabled provider by omitting it from the map, so
// filtering on ProviderStopped alone is already sufficient to never re-enable something a human turned off on purpose.
// There is no second "did the operator mean it?" check to get wrong, because the extension answered that question when it
// graded the stop reason.
func Remediable(providers map[string]string) []string {
	out := make([]string, 0, len(providers))
	for name, state := range providers {
		if state != ProviderStopped {
			continue
		}
		if _, ok := subcommand[name]; !ok {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Subcommand returns the host-app subcommand that re-enables a provider, and whether one exists.
func Subcommand(provider string) (string, bool) {
	cmd, ok := subcommand[provider]
	return cmd, ok
}
