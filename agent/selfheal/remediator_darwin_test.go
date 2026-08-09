//go:build darwin

package selfheal

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fleetdm/edr/agent/codesign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubHostApp writes a shell script that stands in for the host app, recording its argv and exiting with the given code.
func stubHostApp(t *testing.T, exitCode int) (path, argvFile string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "edr")
	argvFile = filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvFile + "\n" +
		"echo 'host app said something' \n" +
		"exit " + strconv.Itoa(exitCode) + "\n"
	// #nosec G306 -- the stub stands in for an executable, so it has to carry the execute bit.
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path, argvFile
}

// spec:agent-status-reporting/the-agent-restores-stopped-capture-providers/remediation-needs-no-console-user
func TestEnableInvokesTheHostAppDirectlyWithNoSessionWrapper(t *testing.T) {
	t.Parallel()
	cases := []struct {
		provider string
		wantSub  string
	}{
		{provider: "content_filter", wantSub: "enable-filter"},
		{provider: "dns_proxy", wantSub: "enable-dns-proxy"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			t.Parallel()
			path, argvFile := stubHostApp(t, 0)
			require.NoError(t, NewRemediator(path).Enable(context.Background(), tc.provider))

			// #nosec G304 -- path is this test's own t.TempDir output, not external input.
			raw, err := os.ReadFile(argvFile)
			require.NoError(t, err)
			argv := strings.Fields(string(raw))

			// The whole argv is the subcommand and nothing else. This is the assertion that matters for the loginwindow
			// case: no `launchctl asuser`, no `sudo -u`, no console-uid lookup anywhere in the invocation. Submitting an
			// OSSystemExtensionRequest would need a user Aqua session, but toggling a provider does not, and a host with
			// nobody logged in is exactly as blind as one with a console session.
			assert.Equal(t, []string{tc.wantSub}, argv)
		})
	}
}

func TestEnableSurfacesTheHostAppOutputOnFailure(t *testing.T) {
	t.Parallel()
	path, _ := stubHostApp(t, 1)
	err := NewRemediator(path).Enable(context.Background(), "content_filter")
	require.Error(t, err)
	// The host app prints its reason rather than encoding it in the exit status, so dropping the output would reduce every
	// failure to a bare "exit status 1" in the agent log and make the escalation undiagnosable.
	assert.Contains(t, err.Error(), "host app said something")
	assert.Contains(t, err.Error(), "enable-filter")
}

func TestEnableRejectsAProviderItCannotRestore(t *testing.T) {
	t.Parallel()
	path, _ := stubHostApp(t, 0)
	err := NewRemediator(path).Enable(context.Background(), "future_provider")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "future_provider")
}

func TestNewRemediatorDefaultsToTheInstalledHostApp(t *testing.T) {
	t.Parallel()
	r, ok := NewRemediator("").(*hostAppRemediator)
	require.True(t, ok)
	assert.Equal(t, HostAppPath, r.path)
}

// signingFixture builds a remediator whose identity check reads from a fixed table instead of the real Security framework.
func signingFixture(t *testing.T, path string, byPath map[string]*codesign.Result) *hostAppRemediator {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	return &hostAppRemediator{
		path:   path,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		evaluate: func(p string) (*codesign.Result, bool) {
			if p == self {
				res, ok := byPath["self"]
				return res, ok
			}
			res, ok := byPath[p]
			return res, ok
		},
	}
}

func TestEnableRefusesAHostAppSignedByAnotherTeam(t *testing.T) {
	t.Parallel()
	// /Applications is drwxrwxr-x root:admin on stock macOS, and renaming a directory needs write on the PARENT, so a
	// non-root admin can swap the whole bundle. This remediator is the only thing that runs that path as root, so without
	// the identity check it would be an admin-to-root escalation.
	path, argvFile := stubHostApp(t, 0)
	r := signingFixture(t, path, map[string]*codesign.Result{
		"self": {TeamID: "FDG8Q7N4CC"},
		path:   {TeamID: "ATTACKER99"},
	})
	err := r.Enable(context.Background(), "content_filter")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to run")
	assert.Contains(t, err.Error(), "ATTACKER99")
	// The substituted binary must not have executed at all.
	_, statErr := os.Stat(argvFile)
	assert.True(t, os.IsNotExist(statErr), "the foreign-signed host app must never be exec'd")
}

func TestEnableAcceptsAHostAppSignedByTheSameTeam(t *testing.T) {
	t.Parallel()
	path, argvFile := stubHostApp(t, 0)
	r := signingFixture(t, path, map[string]*codesign.Result{
		"self": {TeamID: "FDG8Q7N4CC"},
		path:   {TeamID: "FDG8Q7N4CC"},
	})
	require.NoError(t, r.Enable(context.Background(), "content_filter"))
	// #nosec G304 -- path is this test's own t.TempDir output, not external input.
	raw, err := os.ReadFile(argvFile)
	require.NoError(t, err)
	assert.Equal(t, []string{"enable-filter"}, strings.Fields(string(raw)))
}

func TestEnableAllowsAnAdHocAgentBuildWithoutVerifying(t *testing.T) {
	t.Parallel()
	// A dev or QA agent is ad-hoc signed and carries no team, so there is nothing to compare the host app against. Failing
	// closed here would break every local build for no security gain: a dev host is not the threat model.
	path, _ := stubHostApp(t, 0)
	r := signingFixture(t, path, map[string]*codesign.Result{
		"self": {TeamID: ""},
		path:   {TeamID: "ANYTHING"},
	})
	assert.NoError(t, r.Enable(context.Background(), "content_filter"))
}

func TestEnableRefusesWhenTheHostAppSigningCannotBeRead(t *testing.T) {
	t.Parallel()
	path, _ := stubHostApp(t, 0)
	r := signingFixture(t, path, map[string]*codesign.Result{"self": {TeamID: "FDG8Q7N4CC"}})
	err := r.Enable(context.Background(), "content_filter")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not read code signing")
}
