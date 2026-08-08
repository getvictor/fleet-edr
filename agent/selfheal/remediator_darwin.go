//go:build darwin

package selfheal

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/fleetdm/edr/agent/codesign"
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
	path   string
	logger *slog.Logger
	// evaluate reads an on-disk code-signing identity. Injected so both branches of the identity check are testable; a test
	// binary is ad-hoc signed, so against the real Evaluate only the dev-build path would ever be exercised.
	evaluate func(string) (*codesign.Result, bool)
}

// NewRemediator returns the darwin remediator. The host-app path is overridable for tests.
func NewRemediator(path string) Remediator {
	if path == "" {
		path = HostAppPath
	}
	return &hostAppRemediator{path: path, logger: slog.Default(), evaluate: codesign.Evaluate}
}

// verifyHostApp rejects a host app whose code-signing identity does not match the agent's own before the agent, running as
// root, executes it.
//
// This matters because of a directory permission, not a file permission. The bundle and its binary are root-owned and not
// group-writable, but `/Applications` itself is `drwxrwxr-x root:admin` on a stock macOS install, and renaming a directory
// needs write on the PARENT. So any admin user without root can move the real bundle aside and drop their own in its
// place. Nothing else runs that path as root; this remediator is what would turn that into an admin-to-root escalation,
// so the check belongs here rather than being someone else's problem.
//
// The agent and the host app ship in the same pkg and are signed by the same identity, so "same team as me" is the whole
// requirement and needs no build-time configuration. When the AGENT itself carries no team (an ad-hoc dev or QA build)
// there is nothing to compare against, so the check logs and allows: a dev host is not the threat model, and failing
// closed there would break every local build for no security gain.
//
// This narrows rather than closes the race: an attacker who swaps the binary between the check and the exec still wins.
// Closing it entirely means validating the audit token of the process after it starts, which the host app has no channel
// to report through today. Rejecting an unsigned or foreign-signed binary removes the trivial attack, which is the one
// that matters here.
func (r *hostAppRemediator) verifyHostApp(ctx context.Context) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve agent path: %w", err)
	}
	self, ok := r.evaluate(selfPath)
	if !ok {
		return fmt.Errorf("could not read the agent's own code signing at %s", selfPath)
	}
	if self.TeamID == "" {
		r.logger.WarnContext(ctx, "agent is not team-signed, so the host app's identity cannot be verified before running it",
			"host_app", r.path)
		return nil
	}
	host, ok := r.evaluate(r.path)
	if !ok {
		return fmt.Errorf("could not read code signing for %s", r.path)
	}
	if host.TeamID != self.TeamID {
		return fmt.Errorf("refusing to run %s as root: team %q does not match the agent's %q",
			r.path, host.TeamID, self.TeamID)
	}
	return nil
}

func (r *hostAppRemediator) Enable(ctx context.Context, provider string) error {
	sub, ok := Subcommand(provider)
	if !ok {
		return fmt.Errorf("no enable subcommand for provider %q", provider)
	}
	if err := r.verifyHostApp(ctx); err != nil {
		return err
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
