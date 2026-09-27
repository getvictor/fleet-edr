package enrich

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/pkgsign"
)

// A postinstall exec as recorded on edr-dev for issue #1161: bash running the script out of PackageKit's sandbox, with the
// package's own path as the script's first argument.
func installerScriptExec(t *testing.T, ppid int, args ...string) []byte {
	t.Helper()
	if args == nil {
		args = []string{"/bin/bash", "/tmp/PKInstallSandbox.iJ0s6V/Scripts/com.amazon.awsvpnclient.gjgthW/postinstall",
			"/Users/alice/Downloads/AWS_VPN_Client.pkg", "/", "/", "/"}
	}
	raw, err := json.Marshal(map[string]any{
		"event_id": "e1", "event_type": "exec", "timestamp_ns": 1,
		"payload": map[string]any{"pid": 101, "ppid": ppid, "path": "/bin/bash", "args": args},
	})
	require.NoError(t, err)
	return raw
}

const scriptServicePID = 100

func parents(t *testing.T) ParentPath {
	t.Helper()
	return func(pid int) (string, bool) {
		switch pid {
		case scriptServicePID:
			return PackageScriptServicePath, true
		case 200:
			return "/bin/zsh", true
		}
		return "", false
	}
}

// recordingPackageEvaluator answers for any package and remembers which one it was asked about.
type recordingPackageEvaluator struct {
	asked  []string
	result *pkgsign.Result
	ok     bool
}

func (r *recordingPackageEvaluator) eval(path string) (*pkgsign.Result, bool) {
	r.asked = append(r.asked, path)
	return r.result, r.ok
}

func packageSigningOf(t *testing.T, data []byte) (json.RawMessage, bool) {
	t.Helper()
	var evt struct {
		Payload map[string]json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(data, &evt))
	v, ok := evt.Payload["package_signing"]
	return v, ok
}

// spec:endpoint-event-collection/an-installer-script-names-its-package-s-signature/a-script-packagekit-ran-carries-its-package-s-signature
func TestPackageScriptSigning_FillsTheScriptsPackage(t *testing.T) {
	t.Parallel()
	rec := &recordingPackageEvaluator{result: &pkgsign.Result{Signed: true, Notarized: true, TeamID: "94KV3E626L"}, ok: true}
	out := PackageScriptSigning(installerScriptExec(t, scriptServicePID), parents(t), rec.eval)

	assert.Equal(t, []string{"/Users/alice/Downloads/AWS_VPN_Client.pkg"}, rec.asked, "the argument after the script is the package")
	got, ok := packageSigningOf(t, out)
	require.True(t, ok)
	assert.JSONEq(t, `{"signed":true,"notarized":true,"team_id":"94KV3E626L"}`, string(got))

	var evt map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &evt))
	assert.JSONEq(t, `"e1"`, string(evt["event_id"]), "envelope fields survive")
}

// spec:endpoint-event-collection/an-installer-script-names-its-package-s-signature/a-script-from-another-parent-carries-none
//
// The reason the parent is checked at all. The argument is anyone's to write: a script run from a shell can name a signed vendor
// package, and without the check it would carry that vendor's signature into the rule's decision.
func TestPackageScriptSigning_OnlyForScriptsPackageKitRan(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ppid int
	}{
		{"a shell parent naming a signed package", 200},
		{"an unknown parent", 999},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recordingPackageEvaluator{result: &pkgsign.Result{Signed: true, TeamID: "94KV3E626L"}, ok: true}
			in := installerScriptExec(t, tc.ppid)
			assert.Equal(t, in, PackageScriptSigning(in, parents(t), rec.eval))
			assert.Empty(t, rec.asked, "no package is read for an exec PackageKit did not run")
		})
	}
}

// spec:endpoint-event-collection/an-installer-script-names-its-package-s-signature/an-unreadable-package-is-not-reported-as-unsigned
func TestPackageScriptSigning_PassesThrough(t *testing.T) {
	t.Parallel()
	signed := &recordingPackageEvaluator{result: &pkgsign.Result{Signed: true}, ok: true}
	cases := []struct {
		name string
		data []byte
		eval *recordingPackageEvaluator
	}{
		{"an unreadable package", installerScriptExec(t, scriptServicePID), &recordingPackageEvaluator{}},
		{"a compiled script with no package argument", installerScriptExec(t, scriptServicePID,
			"/tmp/PKInstallSandbox.x/Scripts/com.example.y/postinstall"), signed},
		{"a script outside the installer sandbox", installerScriptExec(t, scriptServicePID,
			"/bin/bash", "/tmp/other/postinstall", "/tmp/x.pkg"), signed},
		{"another event type", []byte(`{"event_type":"exit","payload":{"pid":1}}`), signed},
		{"a null payload", []byte(`{"event_type":"exec","payload":null}`), signed},
		{"malformed", []byte(`{"event_type":"exec","payload":`), signed},
		{"already present", []byte(`{"event_type":"exec","payload":{"ppid":100,"args":["/bin/bash",` +
			`"/tmp/PKInstallSandbox.x/Scripts/y/postinstall","/tmp/a.pkg"],"package_signing":{"signed":false}}}`), signed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.data, PackageScriptSigning(tc.data, parents(t), tc.eval.eval))
		})
	}
}

// A compiled postinstall is argv[0] itself, with the package right after it.
func TestPackageArgument(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/p.pkg", packageArgument([]string{"/tmp/PKInstallSandbox.a/Scripts/b/postinstall", "/p.pkg", "/", "/", "/"}))
	assert.Equal(t, "/p.pkg", packageArgument([]string{"/bin/sh", "/tmp/PKInstallSandbox.a/Scripts/b/preinstall", "/p.pkg"}))
	assert.Empty(t, packageArgument([]string{"/tmp/PKInstallSandbox.a/Scripts/b/postinstall"}), "nothing follows the script")
	assert.Empty(t, packageArgument(nil))
}
