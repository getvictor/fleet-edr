package catalog

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/sigmabind"
)

// boundDestructionEvent builds a file_truncate or file_delete event the way the extension emits one, bound to an actor.
func boundDestructionEvent(t *testing.T, eventType, path, subject string) *sigmabind.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"pid": 7, "path": path})
	require.NoError(t, err)
	ev, err := sigmabind.NewOpenEventLazy(
		api.Event{EventID: "e", EventType: eventType, Payload: payload},
		func() (string, error) { return subject, nil })
	require.NoError(t, err)
	return ev
}

// spec:server-detection-rules-engine/destroyed-sudo-policy-is-detected-separately-from-tampering/emptying-a-sudoers-file-fires
// spec:server-detection-rules-engine/destroyed-sudo-policy-is-detected-separately-from-tampering/deleting-a-sudoers-file-fires
// spec:server-detection-rules-engine/destroyed-sudo-policy-is-detected-separately-from-tampering/destroying-a-file-sudo-ignores-does-not-fire
//
// Both destruction shapes and the boundary, as a table so what does and does not count as destroyed policy is auditable at a
// glance.
//
// The `.tmp` and trailing-tilde rows are the load-bearing ones. visudo UNLINKS its own `<name>.tmp` on every run, measured on
// edr-dev, so a rule matching any direct child would report every legitimate sudoers edit as a policy deletion. That is the
// over-match that made sudoers_tamper fire on visudo (#933) arriving through the deletion door, and the same pattern stops it.
func TestSudoersDestroyed_MatchesOnlyPolicySudoWouldLoad(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/sudoers", true},
		{"/private/etc/sudoers", true},
		{"/etc/sudoers.d/admins", true},
		{"/private/etc/sudoers.d/edr-uat", true},
		{"/etc/sudoers.d/foo~bar", true},
		// visudo's own temporary file, removed on every run.
		{"/etc/sudoers.d/admins.tmp", false},
		{"/etc/sudoers.d/backup.old", false},
		{"/etc/sudoers.d/fragment~", false},
		{"/etc/sudoers.d/", false},
		{"/etc/sudoers.d/nested/deeper", false},
		{"/etc/passwd", false},
	}
	for _, eventType := range []string{"file_truncate", "file_delete"} {
		for _, tc := range cases {
			t.Run(eventType+" "+tc.path, func(t *testing.T) {
				t.Parallel()
				ev := boundDestructionEvent(t, eventType, tc.path, "/bin/rm")
				assert.Equal(t, tc.want, sudoersDestroyedDetection().Matches(ev), "%s %s", eventType, tc.path)
			})
		}
	}
}

// spec:server-detection-rules-engine/destroyed-sudo-policy-is-detected-separately-from-tampering/destruction-and-tampering-carry-different-techniques
//
// The mapping is the whole reason this is a separate rule rather than two more event types on sudoers_tamper. Emptying or
// deleting a sudoers file grants nothing, so reporting it under T1548.003 (Abuse Elevation Control Mechanism) would put a
// destruction event on a coverage page under the technique for escalation.
func TestSudoersDestroyed_TechniquesAreRemovalNotEscalation(t *testing.T) {
	t.Parallel()
	destroyed := (&SudoersDestroyed{}).Techniques()
	tampered := (&SudoersTamper{}).Techniques()

	assert.Equal(t, []string{"T1070.004", "T1531"}, destroyed)
	assert.NotContains(t, destroyed, "T1548.003", "destruction grants no elevation, so it must not claim the escalation technique")
	for _, technique := range destroyed {
		assert.NotContains(t, tampered, technique, "the two rules must not collapse onto the same coverage claim")
	}
}

// The finding has to say WHICH destruction happened, because the two leave the host in different states: a truncated file still
// exists and still parses, as an empty policy, while a deleted one is gone and a later `sudo` reports it missing. An analyst
// reading "destroyed" alone would not know which they are looking at.
func TestSudoersDestroyed_DescriptionNamesTheDestruction(t *testing.T) {
	t.Parallel()

	emptied := sudoersDestroyedDescription("file_truncate", "/bin/sh", "/etc/sudoers")
	assert.Contains(t, emptied, "/bin/sh emptied /etc/sudoers")
	assert.NotContains(t, emptied, "deleted")

	deleted := sudoersDestroyedDescription("file_delete", "/bin/rm", "/etc/sudoers.d/admins")
	assert.Contains(t, deleted, "/bin/rm deleted /etc/sudoers.d/admins")
	assert.NotContains(t, deleted, "emptied")
}

// The rule's own event-type guard, exercised through Evaluate rather than through the detection block alone.
//
// Worth its own test for the reason a mutation run proved on #935: every assertion above calls the detection directly, so
// deleting an event type from the guard upstream of it leaves them all green while the rule stops seeing the events entirely.
func TestSudoersDestroyed_FiresThroughTheRule(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersDestroyed{}

	const pid = 7710
	setup := []api.Event{
		{EventID: "sd-fork", HostID: "fixture-host", TimestampNs: 1, EventType: "fork",
			Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":1}`, pid))},
		{EventID: "sd-exec", HostID: "fixture-host", TimestampNs: 2, EventType: "exec",
			Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":1,"path":"/bin/sh"}`, pid))},
	}
	require.NoError(t, s.InsertEvents(ctx, setup))
	require.NoError(t, s.ProcessBatch(ctx, setup))

	for _, eventType := range []string{"file_truncate", "file_delete"} {
		evt := api.Event{
			EventID:      "sd-" + eventType,
			HostID:       "fixture-host",
			TimestampNs:  3,
			IngestedAtNs: time.Now().UnixNano(),
			EventType:    eventType,
			Payload:      json.RawMessage(fmt.Sprintf(`{"pid":%d,"path":"/etc/sudoers"}`, pid)),
		}
		findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
		require.NoError(t, err)
		require.Len(t, findings, 1, "%s must fire through the rule", eventType)
		assert.Equal(t, "sudoers_destroyed", findings[0].RuleID)
	}
}
