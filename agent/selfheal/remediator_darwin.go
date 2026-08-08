//go:build darwin

package selfheal

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// HostAppPath is the host application binary that owns the NetworkExtension configuration. Only this binary can change it:
// the NEFilterManager / NEDNSProxyManager preferences are keyed to the app's code signature, so the agent cannot write them
// directly and shells out instead.
const HostAppPath = "/Applications/Fleet EDR.app/Contents/MacOS/edr"

// enableTimeout bounds one enable. The measured happy path is a few seconds (the provider was back 13 seconds after the
// subcommand returned on edr-dev), but loadFromPreferences / saveToPreferences talk to nesessionmanager, and a wedged
// configuration daemon must not pin this goroutine forever.
const enableTimeout = 60 * time.Second

// hostAppRemediator re-enables a provider by running the host app's enable subcommand.
//
// It runs as whatever the agent runs as, which is root in the LaunchDaemon, and deliberately does NOT wrap the call in
// `launchctl asuser` to reach a console user's Aqua session. Submitting an OSSystemExtensionRequest would need that
// session, but toggling a provider does not: measured on edr-dev, `edr enable-filter` as plain root brought the content
// filter back. That matters because it is what lets a host at the loginwindow, with no console user at all, recover.
type hostAppRemediator struct {
	path string
}

// NewRemediator returns the darwin remediator. The host-app path is overridable for tests.
func NewRemediator(path string) Remediator {
	if path == "" {
		path = HostAppPath
	}
	return &hostAppRemediator{path: path}
}

func (r *hostAppRemediator) Enable(ctx context.Context, provider string) error {
	sub, ok := Subcommand(provider)
	if !ok {
		return fmt.Errorf("no enable subcommand for provider %q", provider)
	}
	ctx, cancel := context.WithTimeout(ctx, enableTimeout)
	defer cancel()

	// #nosec G204 -- neither argument is caller-controlled: r.path is a build-time constant (overridden only by tests) and
	// sub comes from the package's closed subcommand table, which Subcommand already rejected anything not in.
	out, err := exec.CommandContext(ctx, r.path, sub).CombinedOutput()
	if err != nil {
		// The host app prints its failure reason on stdout/stderr rather than encoding it in the exit status, so the output
		// is the diagnostic; without it every failure reads as a bare "exit status 1".
		return fmt.Errorf("%s %s: %w: %s", r.path, sub, err, out)
	}
	return nil
}
