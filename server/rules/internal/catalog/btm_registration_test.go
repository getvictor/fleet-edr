package catalog

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// btmRegistrationEvent is a btm_launch_item_add as the agent uploads it, with item_path as the file URL the extension reports.
func btmRegistrationEvent(t *testing.T, itemType, plist, executable string, cs *codeSigningJSON, managed bool) api.Event {
	t.Helper()
	payload := map[string]any{
		// Built the way the extension's URL is, so a path with a space arrives escaped, as it does from a real host.
		"item_type": itemType, "item_path": (&url.URL{Scheme: "file", Path: plist}).String(), "executable_path": executable,
		"managed":        managed,
		"instigator_pid": 93,
	}
	if cs != nil {
		payload["executable_code_signing"] = map[string]any{
			"team_id": cs.TeamID, "signing_id": cs.SigningID, "flags": 0, "is_platform_binary": cs.IsPlatformBinary,
		}
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return api.Event{EventID: "btm-" + itemType, HostID: "fixture-host", TimestampNs: 1, EventType: "btm_launch_item_add", Payload: raw}
}

// The gate the three persistence rules share. Each case is one reason a registration is not judged, plus the one that is, for each
// item type, so a gate that confused two item types or dropped a skip fails here rather than in only one of the rules.
func TestUntrustedRegistration(t *testing.T) {
	t.Parallel()
	adHoc := &codeSigningJSON{SigningID: "a.out"}
	platform := &codeSigningJSON{SigningID: "com.apple.xprotect", IsPlatformBinary: true}
	cases := []struct {
		name     string
		itemType string
		evt      func(t *testing.T) api.Event
		judged   bool
	}{
		{"an ad-hoc agent", "agent", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/x.plist", "/tmp/x", adHoc, false)
		}, true},
		{"an ad-hoc daemon", "daemon", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "daemon", "/Library/LaunchDaemons/x.plist", "/tmp/x", adHoc, false)
		}, true},
		{"an ad-hoc login item's helper", "login_item", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "login_item", "/Applications/T.app/Contents/Library/LoginItems/H.app", "", adHoc, false)
		}, true},
		{"an ad-hoc app, asked for a login item or an app", "", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "app", "/Applications/T.app/", "", adHoc, false)
		}, true},
		{"a login item, asked for an agent", "agent", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "login_item", "/Applications/T.app/Contents/Library/LoginItems/H.app", "", adHoc, false)
		}, false},
		{"a daemon, asked for an agent", "agent", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "daemon", "/Library/LaunchDaemons/x.plist", "/tmp/x", adHoc, false)
		}, false},
		{"MDM managed", "agent", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/x.plist", "/tmp/x", adHoc, true)
		}, false},
		{"an Apple platform binary", "agent", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/x.plist", "/usr/libexec/x", platform, false)
		}, false},
		{"no readable signature", "agent", func(t *testing.T) api.Event {
			t.Helper()
			return btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/x.plist", "/tmp/x", nil, false)
		}, false},
		{"another event type", "agent", func(t *testing.T) api.Event {
			t.Helper()
			evt := btmRegistrationEvent(t, "agent", "/Library/LaunchAgents/x.plist", "/tmp/x", adHoc, false)
			evt.EventType = "exec"
			return evt
		}, false},
		{"a malformed payload", "agent", func(*testing.T) api.Event {
			return api.Event{EventType: "btm_launch_item_add", Payload: json.RawMessage(`{"item_type":"agent","item_path":`)}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			itemTypes := []string{tc.itemType}
			if tc.itemType == "" {
				itemTypes = []string{"login_item", "app"}
			}
			_, judged := untrustedRegistration(tc.evt(t), itemTypes...)
			assert.Equal(t, tc.judged, judged)
		})
	}
}

func TestBTMItemPath(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/Library/LaunchAgents/x.plist", btmItemPath("file:///Library/LaunchAgents/x.plist"))
	assert.Equal(t, "/Users/jane doe/Library/LaunchAgents/x.plist", btmItemPath("file:///Users/jane%20doe/Library/LaunchAgents/x.plist"),
		"a URL escapes a space; the path an operator writes does not")
	assert.Equal(t, "/Library/LaunchAgents/x.plist", btmItemPath("/Library/LaunchAgents/x.plist"), "a path is already a path")
}

func TestPathSubject(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "launchagent:/Library/LaunchAgents/x.plist", pathSubject("launchagent", "/Library/LaunchAgents/x.plist"))
	long := "/Library/LaunchAgents/" + strings.Repeat("a", 300) + ".plist"
	got := pathSubject("launchagent", long)
	assert.LessOrEqual(t, len(got), subjectColumnLimit)
	assert.Equal(t, got, pathSubject("launchagent", long), "stable for one path")
	assert.NotEqual(t, got, pathSubject("launchagent", long+"x"), "distinct for another")
}
