package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// installerChain is the shape of the dogfood alerts in issue #1161: PackageKit's script service runs bash on a postinstall out of
// its sandbox, with the package's path as the script's first argument. signing is the agent's package_signing, or "" for none.
func installerChain(t *testing.T, parentPath, signing string) []api.Event {
	t.Helper()
	payload := map[string]any{
		"pid": 200, "ppid": 100, "path": "/bin/bash", "uid": 0, "gid": 0,
		"args": []string{"/bin/bash", "/tmp/PKInstallSandbox.66P7MB/Scripts/com.amazon.awsvpnclient.rrRQ2l/postinstall",
			"/Users/alice/Downloads/AWS_VPN_Client.pkg", "/", "/", "/"},
	}
	if signing != "" {
		payload["package_signing"] = json.RawMessage(signing)
	}
	script, err := json.Marshal(payload)
	require.NoError(t, err)
	return []api.Event{
		{EventID: "fork-svc", HostID: "host-a", TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":1}`)},
		{EventID: "exec-svc", HostID: "host-a", TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":1,"path":"` + parentPath + `","args":["package_script_service"],"uid":0,"gid":0}`)},
		{EventID: "fork-script", HostID: "host-a", TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-script", HostID: "host-a", TimestampNs: 2100, EventType: "exec", Payload: script},
	}
}

const amazonSigned = `{"signed":true,"notarized":true,"team_id":"94KV3E626L"}`

func evaluateInstaller(t *testing.T, excl api.ExclusionResolver, events []api.Event) []api.Finding {
	t.Helper()
	s := openCatalogStore(t)
	require.NoError(t, s.InsertEvents(t.Context(), events))
	materialize(t, s, events)
	findings, err := (&SuspiciousExec{Exclusions: excl}).Evaluate(t.Context(), events, s.GraphReader())
	require.NoError(t, err)
	return findings
}

func packageTeam(team string) *fakeExclusions {
	return &fakeExclusions{entries: []fakeExcl{{ruleID: "suspicious_exec", matchType: api.ExclusionMatchPackageTeamID, value: team}}}
}

// spec:server-detection-rules-engine/an-installer-script-is-waived-by-its-package-signer/a-vendor-s-installer-is-waived-by-its-package-team
func TestSuspiciousExecInstaller_WaivedByThePackagesTeam(t *testing.T) {
	t.Parallel()
	chain := installerChain(t, packageScriptServicePath, amazonSigned)
	require.Len(t, evaluateInstaller(t, nil, chain), 1, "the fixture fires with no exclusion")
	assert.Empty(t, evaluateInstaller(t, packageTeam("94KV3E626L"), chain))
	// Notarization is context, not a condition: an in-house Developer ID package deployed by MDM is commonly not notarized, and
	// the operator's team exclusion is the trust decision.
	unnotarized := installerChain(t, packageScriptServicePath, `{"signed":true,"notarized":false,"team_id":"94KV3E626L"}`)
	assert.Empty(t, evaluateInstaller(t, packageTeam("94KV3E626L"), unnotarized))
	assert.Len(t, evaluateInstaller(t, packageTeam("OTHERTEAM1"), chain), 1, "another vendor's team waives nothing")
}

// spec:server-detection-rules-engine/an-installer-script-is-waived-by-its-package-signer/only-a-trusted-package-signature-counts
//
// An unsigned package names no team, and one whose certificate macOS does not trust names whatever its signer typed. Neither may
// reach an exclusion, even one whose value matches the team it claims.
func TestSuspiciousExecInstaller_OnlyATrustedSignatureCounts(t *testing.T) {
	t.Parallel()
	for name, signing := range map[string]string{
		"no signature reported":         "",
		"unsigned":                      `{"signed":false,"notarized":false,"team_id":""}`,
		"untrusted but claiming a team": `{"signed":false,"notarized":false,"team_id":"94KV3E626L"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Len(t, evaluateInstaller(t, packageTeam("94KV3E626L"), installerChain(t, packageScriptServicePath, signing)), 1)
		})
	}
}

// spec:server-detection-rules-engine/an-installer-script-is-waived-by-its-package-signer/a-signature-outside-packagekit-counts-for-nothing
//
// The agent attaches a package signature only under PackageKit's service, and the rule checks again: a chain under any other
// parent carrying one (a fabricated or replayed event) must not be waived by it.
func TestSuspiciousExecInstaller_OutsidePackageKitTheSignatureCountsForNothing(t *testing.T) {
	t.Parallel()
	chain := installerChain(t, "/Applications/Evil.app/Contents/MacOS/Evil", amazonSigned)
	assert.Len(t, evaluateInstaller(t, packageTeam("94KV3E626L"), chain), 1)
}

// The alert names the package and who signed it, which is what an analyst needs to judge an install at a glance.
func TestSuspiciousExecInstaller_TheAlertNamesThePackage(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		signing string
		want    string
	}{
		"signed": {amazonSigned, "(installing /Users/alice/Downloads/AWS_VPN_Client.pkg, signed by team 94KV3E626L, notarized)"},
		"signed, not notarized": {`{"signed":true,"notarized":false,"team_id":"94KV3E626L"}`,
			"(installing /Users/alice/Downloads/AWS_VPN_Client.pkg, signed by team 94KV3E626L, not notarized)"},
		"unsigned": {`{"signed":false,"notarized":false,"team_id":""}`, "(installing /Users/alice/Downloads/AWS_VPN_Client.pkg, unsigned)"},
		"unknown":  {"", "(installing /Users/alice/Downloads/AWS_VPN_Client.pkg)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			findings := evaluateInstaller(t, nil, installerChain(t, packageScriptServicePath, tc.signing))
			require.Len(t, findings, 1)
			assert.Contains(t, findings[0].Description, tc.want)
		})
	}
}
