package catalog

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

const (
	chromeProfile  = "/Users/alice/Library/Application Support/Google/Chrome/Default/"
	firefoxProfile = "/Users/alice/Library/Application Support/Firefox/Profiles/a1b2c3.default-release/"
)

// credentialOpen is an open of path by pid, the shape the credential-store client reports. Each event gets its own ID, since a
// batch decodes an event once per ID.
func credentialOpen(t *testing.T, pid int, path string) api.Event {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pid": pid, "path": path, "flags": 0})
	require.NoError(t, err)
	return api.Event{EventID: fmt.Sprintf("%d:%s", pid, path), HostID: "fixture-host", TimestampNs: 1, EventType: "open", Payload: raw}
}

// openers are the processes the tests open files as, by pid.
func openers() *perPIDGraphReader {
	sig := func(team, signingID string, platform bool) api.NullRawJSON {
		raw, _ := json.Marshal(map[string]any{"team_id": team, "signing_id": signingID, "flags": 0, "is_platform_binary": platform})
		return api.NullRawJSON(raw)
	}
	return &perPIDGraphReader{procByPID: map[int]*api.Process{
		100: {ID: 1, PID: 100, Path: "/bin/cp", CodeSigning: sig("", "com.apple.cp", true)},
		200: {ID: 2, PID: 200, Path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			CodeSigning: sig("EQHXZ8M8AV", "com.google.Chrome", false)},
		300: {ID: 3, PID: 300, Path: "/System/Library/CoreServices/TimeMachine/backupd", CodeSigning: sig("", "com.apple.backupd", true)},
		400: {ID: 4, PID: 400, Path: "/tmp/backupd", CodeSigning: sig("", "com.apple.backupd", false)},
		500: {ID: 5, PID: 500, Path: "/Applications/Firefox.app/Contents/MacOS/firefox",
			CodeSigning: sig("43AQ936H96", "org.mozilla.firefox", false)},
		600: {ID: 6, PID: 600, Path: "/Applications/Backblaze.app/Contents/MacOS/bztransmit",
			CodeSigning: sig("QSNG5JS6FG", "com.backblaze.bztransmit", false)},
		// A signature whose team decodes before a later field fails to: the whole blob must be discarded, not half of it.
		700: {ID: 7, PID: 700, Path: "/tmp/stealer", CodeSigning: api.NullRawJSON(`{"team_id":"EQHXZ8M8AV","is_platform_binary":"yes"}`)},
	}}
}

func evaluateCredentialRead(t *testing.T, excl api.ExclusionResolver, events ...api.Event) []api.Finding {
	t.Helper()
	findings, err := (&CredentialBrowserStoreRead{Exclusions: excl}).Evaluate(t.Context(), events, openers())
	require.NoError(t, err)
	return findings
}

// spec:server-detection-rules-engine/browser-credential-theft-is-reported/another-program-opening-a-credential-store-fires
func TestCredentialBrowserStoreRead_AnotherProgramOpeningACredentialStoreFires(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		chromeProfile + "Login Data":                                                "/bin/cp opened Chrome's Login Data",
		chromeProfile + "Network/Cookies":                                           "/bin/cp opened Chrome's Cookies",
		"/Users/alice/Library/Application Support/Google/Chrome/Local State":        "/bin/cp opened Chrome's Local State",
		firefoxProfile + "key4.db":                                                  "/bin/cp opened Firefox's key4.db",
		"/Users/alice/Library/Application Support/Arc/User Data/Profile 1/Web Data": "/bin/cp opened Arc's Web Data",
	}
	for path, description := range cases {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			findings := evaluateCredentialRead(t, nil, credentialOpen(t, 100, path))
			require.Len(t, findings, 1)
			assert.Equal(t, "credential_browser_store_read", findings[0].RuleID)
			assert.Equal(t, api.SeverityHigh, findings[0].Severity)
			assert.Equal(t, description+": browser credential theft (MITRE T1555.003)", findings[0].Description)
			assert.Equal(t, int64(1), findings[0].ProcessID, "the alert opens on the reading process")
		})
	}
}

// spec:server-detection-rules-engine/browser-credential-theft-is-reported/the-browser-and-apple-s-backup-and-indexing-services-do-not-fire
func TestCredentialBrowserStoreRead_TheBrowserAndApplesServicesDoNotFire(t *testing.T) {
	t.Parallel()
	assert.Empty(t, evaluateCredentialRead(t, nil,
		credentialOpen(t, 200, chromeProfile+"Login Data"),
		credentialOpen(t, 500, firefoxProfile+"logins.json"),
		credentialOpen(t, 300, chromeProfile+"Cookies"),
		credentialOpen(t, 100, chromeProfile+"Preferences"),
		credentialOpen(t, 100, "/Users/alice/Documents/Login Data"),
		credentialOpen(t, 100, chromeProfile+"Login Data-journal"),
	))
	// The owner check is by the store's browser: Chrome's team reading Firefox's store is not Firefox reading its own.
	assert.Len(t, evaluateCredentialRead(t, nil, credentialOpen(t, 200, firefoxProfile+"logins.json")), 1)
	// Apple's services are judged by the platform-qualified identifier, which a planted binary cannot claim.
	assert.Len(t, evaluateCredentialRead(t, nil, credentialOpen(t, 400, chromeProfile+"Cookies")), 1)
}

// spec:server-detection-rules-engine/browser-credential-theft-is-reported/an-opener-is-waived-by-its-signer-or-path
func TestCredentialBrowserStoreRead_AnOpenerIsWaivedBySignerOrPath(t *testing.T) {
	t.Parallel()
	const rule = "credential_browser_store_read"
	cases := []struct {
		name  string
		excl  fakeExcl
		fires bool
	}{
		{"by team", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchTeamID, value: "QSNG5JS6FG"}, false},
		{"by qualified signing id", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchSigningID,
			value: "QSNG5JS6FG:com.backblaze.bztransmit"}, false},
		{"by path", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchPathGlob, value: "/Applications/Backblaze.app/*"}, false},
		{"another rule's exclusion", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchTeamID, value: "QSNG5JS6FG"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := evaluateCredentialRead(t, &fakeExclusions{entries: []fakeExcl{tc.excl}}, credentialOpen(t, 600, chromeProfile+"Login Data"))
			assert.Equal(t, tc.fires, len(findings) == 1)
		})
	}
}

// Every browser in the table, each against the team written out here rather than read back from the rule's own table, so a typo in
// a row's directory or team fails: the directory would stop the store being recognized, and the team would either silence another
// program or report the browser itself.
func TestCredentialBrowserStoreRead_EveryBrowserIsRecognizedAndTrustsOnlyItsOwnTeam(t *testing.T) {
	t.Parallel()
	browsers := []struct {
		name, root, team, file string
	}{
		{"Chrome", "/Library/Application Support/Google/Chrome/Default/", "EQHXZ8M8AV", "Login Data"},
		{"Brave", "/Library/Application Support/BraveSoftware/Brave-Browser/Default/", "KL8N8XSYF4", "Login Data"},
		{"Edge", "/Library/Application Support/Microsoft Edge/Profile 2/", "UBF8T346G9", "Web Data"},
		{"Arc", "/Library/Application Support/Arc/User Data/Default/", "S6N382Y83G", "Cookies"},
		{"Vivaldi", "/Library/Application Support/Vivaldi/Default/", "4XF3XNRN6Y", "Login Data For Account"},
		{"Firefox", "/Library/Application Support/Firefox/Profiles/x1.default/", "43AQ936H96", "logins.json"},
	}
	for _, b := range browsers {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			path := "/Users/alice" + b.root + b.file
			raw, err := json.Marshal(map[string]any{"team_id": b.team, "signing_id": "x", "flags": 0, "is_platform_binary": false})
			require.NoError(t, err)
			graph := &perPIDGraphReader{procByPID: map[int]*api.Process{
				100: {ID: 1, PID: 100, Path: "/bin/cp"},
				200: {ID: 2, PID: 200, Path: "/Applications/" + b.name + ".app/Contents/MacOS/" + b.name, CodeSigning: api.NullRawJSON(raw)},
			}}
			findings, err := (&CredentialBrowserStoreRead{}).Evaluate(t.Context(), []api.Event{credentialOpen(t, 100, path)}, graph)
			require.NoError(t, err)
			require.Len(t, findings, 1, "another program opening %s's %s", b.name, b.file)
			assert.Contains(t, findings[0].Description, b.name+"'s "+b.file)

			own, err := (&CredentialBrowserStoreRead{}).Evaluate(t.Context(), []api.Event{credentialOpen(t, 200, path)}, graph)
			require.NoError(t, err)
			assert.Empty(t, own, "%s reading its own store", b.name)
		})
	}
}

// A signature blob that fails to decode names no team, however much of it decoded before the failure, so it cannot pass the
// owner check.
func TestCredentialBrowserStoreRead_AHalfDecodedSignatureTrustsNothing(t *testing.T) {
	t.Parallel()
	assert.Len(t, evaluateCredentialRead(t, nil, credentialOpen(t, 700, chromeProfile+"Login Data")), 1)
}

// The rule reports each open it judges, and the engine keeps one open alert per process: two stores opened by one process are one
// alert because their findings share the process they are linked to, which is the dedup key when a finding sets no subject.
func TestCredentialBrowserStoreRead_OneProcessOpeningSeveralStoresIsOneAlert(t *testing.T) {
	t.Parallel()
	findings := evaluateCredentialRead(t, nil,
		credentialOpen(t, 100, chromeProfile+"Login Data"),
		credentialOpen(t, 100, chromeProfile+"Network/Cookies"),
	)
	require.Len(t, findings, 2)
	assert.Equal(t, findings[0].ProcessID, findings[1].ProcessID)
	assert.Empty(t, findings[0].Subject, "no subject, so the engine dedups on the process")
}
