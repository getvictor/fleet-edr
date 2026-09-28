package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// installerScriptEvent is an installer script's exec in the shape PackageKit runs it: a shell with the script from its sandbox as
// argv[1] and the package as argv[2]. signing is the package_signing object the agent attaches, or "" for none.
func installerScriptEvent(t *testing.T, id, script, pkg, signing string) api.Event {
	t.Helper()
	args, err := json.Marshal([]string{"/bin/sh", script, pkg, "/", "/", "/"})
	require.NoError(t, err)
	payload := `{"pid":6100,"ppid":6000,"path":"/bin/sh","args":` + string(args)
	if signing != "" {
		payload += `,"package_signing":` + signing
	}
	return api.Event{EventID: id, HostID: "fixture-host", TimestampNs: 1, EventType: "exec", Payload: json.RawMessage(payload + "}")}
}

const (
	postinstall = "/tmp/PKInstallSandbox.iJ0s6V/Scripts/com.example.pkg.gjgthW/postinstall"
	preinstall  = "/tmp/PKInstallSandbox.iJ0s6V/Scripts/com.example.pkg.gjgthW/preinstall"
	evilPackage = "/Users/alice/Downloads/Evil Tool.pkg"
	unsigned    = `{"signed":false,"notarized":false,"team_id":""}`
)

func evaluateInstallerPackage(t *testing.T, excl api.ExclusionResolver, events ...api.Event) []api.Finding {
	t.Helper()
	graph := &perPIDGraphReader{procByPID: map[int]*api.Process{6100: {ID: 77, PID: 6100, Path: "/bin/sh"}}}
	findings, err := (&InstallerUnsignedPackage{Exclusions: excl}).Evaluate(t.Context(), events, graph)
	require.NoError(t, err)
	return findings
}

// spec:server-detection-rules-engine/an-unsigned-installer-package-is-reported/an-unsigned-package-s-script-fires
func TestInstallerUnsignedPackage_AnUnsignedPackagesScriptFires(t *testing.T) {
	t.Parallel()
	evt := installerScriptEvent(t, "post", postinstall, evilPackage, unsigned)
	findings := evaluateInstallerPackage(t, nil, evt)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "installer_unsigned_package", f.RuleID)
	assert.Equal(t, api.SeverityHigh, f.Severity)
	assert.Equal(t, "Installer script "+postinstall+" ran from unsigned or untrusted package "+evilPackage, f.Description)
	assert.Equal(t, int64(77), f.ProcessID, "the alert opens on the script's process")
	assert.Equal(t, []string{"post"}, f.EventIDs)
}

// spec:server-detection-rules-engine/an-unsigned-installer-package-is-reported/a-signed-package-or-an-ordinary-exec-does-not-fire
func TestInstallerUnsignedPackage_ASignedPackageOrAnOrdinaryExecDoesNotFire(t *testing.T) {
	t.Parallel()
	signed := installerScriptEvent(t, "signed", postinstall, evilPackage, `{"signed":true,"notarized":false,"team_id":"94KV3E626L"}`)
	// The same argv with no signature is what every exec that is not an installer script looks like to this rule: the agent
	// attaches a signature only under PackageKit's script service.
	ordinary := installerScriptEvent(t, "ordinary", postinstall, evilPackage, "")
	assert.Empty(t, evaluateInstallerPackage(t, nil, signed, ordinary))
}

// spec:server-detection-rules-engine/an-unsigned-installer-package-is-reported/one-alert-per-package
//
// A package's preinstall and postinstall are separate execs. They share the package's subject, so the engine keeps one open alert
// for the install, while a second package is its own.
func TestInstallerUnsignedPackage_OneAlertPerPackage(t *testing.T) {
	t.Parallel()
	pre := installerScriptEvent(t, "pre", preinstall, evilPackage, unsigned)
	post := installerScriptEvent(t, "post", postinstall, evilPackage, unsigned)
	other := installerScriptEvent(t, "other", postinstall, "/Users/alice/Downloads/Other.pkg", unsigned)
	findings := evaluateInstallerPackage(t, nil, pre, post, other)

	require.Len(t, findings, 3)
	assert.Equal(t, findings[0].Subject, findings[1].Subject, "one package's scripts share a subject")
	assert.Equal(t, "installerpkg:"+evilPackage, findings[0].Subject)
	assert.NotEqual(t, findings[0].Subject, findings[2].Subject, "another package is another alert")
}

// spec:server-detection-rules-engine/an-unsigned-installer-package-is-reported/an-unsigned-package-is-waived-by-its-path
func TestInstallerUnsignedPackage_WaivedByItsPath(t *testing.T) {
	t.Parallel()
	excl := &fakeExclusions{entries: []fakeExcl{
		{ruleID: "installer_unsigned_package", matchType: api.ExclusionMatchPathGlob, value: "/Users/alice/Downloads/Evil*.pkg"},
	}}
	assert.Empty(t, evaluateInstallerPackage(t, excl, installerScriptEvent(t, "post", postinstall, evilPackage, unsigned)))

	elsewhere := &fakeExclusions{entries: []fakeExcl{
		{ruleID: "suspicious_exec", matchType: api.ExclusionMatchPathGlob, value: "/Users/alice/Downloads/Evil*.pkg"},
	}}
	assert.Len(t, evaluateInstallerPackage(t, elsewhere, installerScriptEvent(t, "post", postinstall, evilPackage, unsigned)), 1,
		"an exclusion saved for another rule does not silence this one")
}
