package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// authorizedKeysEvent is a write-mode open, or a rename, of path by pid 12100, whose process is a shell.
func authorizedKeysEvent(t *testing.T, eventType, path string) api.Event {
	t.Helper()
	payload := map[string]any{"pid": 12100, "path": path, "flags": 1537}
	if eventType == "file_rename" {
		payload = map[string]any{"pid": 12100, "source_path": "/tmp/k", "path": path}
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	// Each event its own ID: a batch decodes an event once per ID, so events sharing one would all be judged as the first.
	return api.Event{EventID: eventType + ":" + path, HostID: "fixture-host", TimestampNs: 1, EventType: eventType, Payload: raw}
}

func evaluateAuthorizedKeys(t *testing.T, excl api.ExclusionResolver, events ...api.Event) []api.Finding {
	t.Helper()
	graph := &perPIDGraphReader{procByPID: map[int]*api.Process{12100: {ID: 88, PID: 12100, Path: "/bin/zsh"}}}
	findings, err := (&PersistenceSSHAuthorizedKeys{Exclusions: excl}).Evaluate(t.Context(), events, graph)
	require.NoError(t, err)
	return findings
}

// spec:server-detection-rules-engine/ssh-authorized-keys-changes-are-reported/a-key-file-written-in-any-home-fires
func TestPersistenceSSHAuthorizedKeys_AKeyFileWrittenInAnyHomeFires(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/Users/alice/.ssh/authorized_keys",
		"/private/var/root/.ssh/authorized_keys",
		"/Users/alice/.ssh/authorized_keys2",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			findings := evaluateAuthorizedKeys(t, nil, authorizedKeysEvent(t, "open", path))
			require.Len(t, findings, 1)
			assert.Equal(t, "persistence_ssh_authorized_keys", findings[0].RuleID)
			assert.Equal(t, api.SeverityMedium, findings[0].Severity)
			assert.Equal(t, "/bin/zsh wrote "+path+": SSH key persistence (MITRE T1098.004)", findings[0].Description)
			assert.Equal(t, int64(88), findings[0].ProcessID)
		})
	}
}

// spec:server-detection-rules-engine/ssh-authorized-keys-changes-are-reported/a-key-file-renamed-into-place-fires
func TestPersistenceSSHAuthorizedKeys_AKeyFileRenamedIntoPlaceFires(t *testing.T) {
	t.Parallel()
	findings := evaluateAuthorizedKeys(t, nil, authorizedKeysEvent(t, "file_rename", "/Users/alice/.ssh/authorized_keys"))
	require.Len(t, findings, 1)
	assert.Equal(t, "/bin/zsh renamed a file onto /Users/alice/.ssh/authorized_keys: SSH key persistence (MITRE T1098.004)",
		findings[0].Description)
}

// spec:server-detection-rules-engine/ssh-authorized-keys-changes-are-reported/another-file-does-not-fire
func TestPersistenceSSHAuthorizedKeys_AnotherFileDoesNotFire(t *testing.T) {
	t.Parallel()
	assert.Empty(t, evaluateAuthorizedKeys(t, nil,
		authorizedKeysEvent(t, "open", "/Users/alice/.ssh/known_hosts"),
		authorizedKeysEvent(t, "open", "/Users/alice/.ssh/authorized_keys.bak"),
		authorizedKeysEvent(t, "open", "/Users/alice/authorized_keys"),
	))
}

// spec:server-detection-rules-engine/ssh-authorized-keys-changes-are-reported/a-writer-is-waived-by-its-path
func TestPersistenceSSHAuthorizedKeys_AWriterIsWaivedByItsPath(t *testing.T) {
	t.Parallel()
	evt := authorizedKeysEvent(t, "open", "/Users/alice/.ssh/authorized_keys")
	excl := &fakeExclusions{entries: []fakeExcl{
		{ruleID: "persistence_ssh_authorized_keys", matchType: api.ExclusionMatchPathGlob, value: "/bin/zsh"},
	}}
	assert.Empty(t, evaluateAuthorizedKeys(t, excl, evt))

	elsewhere := &fakeExclusions{entries: []fakeExcl{
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/bin/zsh"},
	}}
	assert.Len(t, evaluateAuthorizedKeys(t, elsewhere, evt), 1, "an exclusion saved for another rule does not silence this one")
}
