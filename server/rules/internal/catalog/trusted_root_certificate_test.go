package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

func securityExec(t *testing.T, path string, args ...string) api.Event {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pid": 7700, "ppid": 1, "path": path, "args": args})
	require.NoError(t, err)
	// Each event its own ID: a batch decodes an event once per ID, so events sharing one would all be judged as the first.
	return api.Event{EventID: strings.Join(args, " "), HostID: "fixture-host", TimestampNs: 1, EventType: "exec", Payload: raw}
}

func evaluateTrustedRoot(t *testing.T, events ...api.Event) []api.Finding {
	t.Helper()
	graph := &perPIDGraphReader{procByPID: map[int]*api.Process{7700: {ID: 99, PID: 7700, Path: "/usr/bin/security"}}}
	findings, err := (&TrustedRootCertificate{}).Evaluate(t.Context(), events, graph)
	require.NoError(t, err)
	return findings
}

// spec:server-detection-rules-engine/a-certificate-trusted-from-the-command-line-is-reported/security-writing-trust-settings-fires
func TestTrustedRootCertificate_SecurityWritingTrustSettingsFires(t *testing.T) {
	t.Parallel()
	cases := map[string][]string{
		"add-trusted-cert": {
			"security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", "/tmp/r.pem",
		},
		"trust-settings-import": {"security", "trust-settings-import", "-d", "/tmp/trust.plist"},
	}
	for sub, args := range cases {
		t.Run(sub, func(t *testing.T) {
			t.Parallel()
			findings := evaluateTrustedRoot(t, securityExec(t, "/usr/bin/security", args...))
			require.Len(t, findings, 1)
			assert.Equal(t, "trusted_root_certificate", findings[0].RuleID)
			assert.Equal(t, api.SeverityHigh, findings[0].Severity)
			assert.Contains(t, findings[0].Description, `/usr/bin/security invoked with "`+sub+`": `)
			assert.Equal(t, int64(99), findings[0].ProcessID)
		})
	}
}

// spec:server-detection-rules-engine/a-certificate-trusted-from-the-command-line-is-reported/other-uses-of-security-do-not-fire
func TestTrustedRootCertificate_OtherUsesOfSecurityDoNotFire(t *testing.T) {
	t.Parallel()
	assert.Empty(t, evaluateTrustedRoot(t,
		securityExec(t, "/usr/bin/security", "security", "add-certificates", "/tmp/intermediate.pem"),
		securityExec(t, "/usr/bin/security", "security", "help", "add-trusted-cert"),
		securityExec(t, "/usr/bin/security", "security", "find-certificate", "-a"),
		securityExec(t, "/tmp/security", "security", "add-trusted-cert", "/tmp/r.pem"),
		securityExec(t, "/usr/bin/security", "security", "-h", "add-trusted-cert"),
		securityExec(t, "/usr/bin/security", "security", "-q", "-h", "trust-settings-import"),
		securityExec(t, "/usr/bin/security", "security", "add-trusted-cert", "-d", "-r", "deny", "/tmp/r.pem"),
		securityExec(t, "/usr/bin/security", "security", "add-trusted-cert", "-r", "unspecified", "/tmp/r.pem"),
	))
}

// spec:server-detection-rules-engine/a-certificate-trusted-from-the-command-line-is-reported/security-writing-trust-settings-fires
//
// The alert says what the command does: add-trusted-cert trusts a certificate, while an import applies whatever its file holds,
// deny entries included. A trusting result type given explicitly still fires, and a later flag that is not -h does not hide it.
func TestTrustedRootCertificate_SaysWhatTheCommandDoes(t *testing.T) {
	t.Parallel()
	explicit := securityExec(t, "/usr/bin/security", "security", "-v", "add-trusted-cert", "-r", "trustAsRoot", "/tmp/r.pem")
	added := evaluateTrustedRoot(t, explicit)
	require.Len(t, added, 1)
	assert.Equal(t, `/usr/bin/security invoked with "add-trusted-cert": makes the host trust a certificate (MITRE T1553.004)`,
		added[0].Description)

	imported := evaluateTrustedRoot(t, securityExec(t, "/usr/bin/security", "security", "trust-settings-import", "-d", "/tmp/t.plist"))
	require.Len(t, imported, 1)
	assert.Equal(t, `/usr/bin/security invoked with "trust-settings-import": imports certificate trust settings, which can make the `+
		`host trust a certificate (MITRE T1553.004)`, imported[0].Description)
}
