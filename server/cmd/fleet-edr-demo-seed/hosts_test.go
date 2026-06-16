package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/test/fakeagent"
)

// TestLoadHostEnvelopes_EachManifestHost confirms every embedded host corpus parses, carries a single host_id, and is scrubbed:
// no snapshot_heartbeat (dropped by the scrub) and the three telemetry streams (exec, network_connect, dns_query) are present, so
// a replayed host actually shows the deep-tree + correlated-DNS data the demo promises.
func TestLoadHostEnvelopes_EachManifestHost(t *testing.T) {
	t.Parallel()
	for _, host := range hostManifest {
		t.Run(host.File, func(t *testing.T) {
			t.Parallel()
			envs, hostID, err := loadHostEnvelopes(host.File)
			require.NoError(t, err)
			require.NotEmpty(t, envs)
			assert.NotEmpty(t, hostID)

			types := map[string]int{}
			for _, e := range envs {
				assert.Equal(t, hostID, e.HostID, "every envelope shares the host's UUID")
				types[e.EventType]++
			}
			assert.Zero(t, types["snapshot_heartbeat"], "scrub must drop snapshot_heartbeat noise")
			for _, want := range []string{"exec", "network_connect", "dns_query"} {
				assert.Positive(t, types[want], "captured host must carry %s events", want)
			}
		})
	}
}

func TestShiftEnvelopesToRecent(t *testing.T) {
	t.Parallel()

	t.Run("empty input is returned unchanged", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, shiftEnvelopesToRecent(nil, time.Now()))
	})

	t.Run("latest event lands at now-recentTailOffset and deltas are preserved", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_900_000_000, 0)
		envs := []fakeagent.Envelope{
			{TimestampNs: 1000},
			{TimestampNs: 4000}, // latest
			{TimestampNs: 2500},
		}
		shiftEnvelopesToRecent(envs, now)

		wantLatest := now.Add(-recentTailOffset).UnixNano()
		assert.Equal(t, wantLatest, envs[1].TimestampNs, "latest event pinned to now-offset")
		// Inter-event deltas from the original capture are preserved exactly.
		assert.Equal(t, int64(4000-1000), envs[1].TimestampNs-envs[0].TimestampNs)
		assert.Equal(t, int64(4000-2500), envs[1].TimestampNs-envs[2].TimestampNs)
		// Every event is in the past (never future-dated).
		assert.Less(t, envs[1].TimestampNs, now.UnixNano())
	})
}

// TestOffsetScenarioPIDs confirms every pid-like field is shifted by the offset (including InstigatorPID, used by
// btm_launch_item_add events) while kernel/launchd sentinels (values <= 1) are preserved so the subtree still roots at pid 1.
func TestOffsetScenarioPIDs(t *testing.T) {
	t.Parallel()
	sc := &fakeagent.Scenario{Timeline: []fakeagent.Event{
		{Type: "fork", ChildPID: 100, ParentPID: 1},
		{Type: "btm_launch_item_add", PID: 200, PPID: 100, InstigatorPID: 50},
		{Type: "exec", PID: 1, PPID: 1}, // sentinels
	}}
	offsetScenarioPIDs(sc, 5_000_000)

	assert.Equal(t, 5_000_100, sc.Timeline[0].ChildPID)
	assert.Equal(t, 1, sc.Timeline[0].ParentPID, "launchd sentinel preserved")
	assert.Equal(t, 5_000_200, sc.Timeline[1].PID)
	assert.Equal(t, 5_000_100, sc.Timeline[1].PPID)
	assert.Equal(t, 5_000_050, sc.Timeline[1].InstigatorPID, "instigator pid is offset too")
	assert.Equal(t, 1, sc.Timeline[2].PID, "pid <= 1 preserved")
	assert.Equal(t, 1, sc.Timeline[2].PPID)
}

// TestPickAttackAnchorPID confirms the anchor is the last interactive shell in the capture, that non-shell execs and non-exec
// events are ignored, and that a shell-less capture yields 0 (so the attack falls back to its launchd root).
func TestPickAttackAnchorPID(t *testing.T) {
	t.Parallel()

	exec := func(pid int, path string) fakeagent.Envelope {
		payload, err := json.Marshal(map[string]any{"pid": pid, "path": path})
		require.NoError(t, err)
		return fakeagent.Envelope{EventType: "exec", Payload: payload}
	}
	execAt := func(pid int, path string, ts int64) fakeagent.Envelope {
		e := exec(pid, path)
		e.TimestampNs = ts
		return e
	}

	t.Run("latest shell exec by timestamp wins", func(t *testing.T) {
		t.Parallel()
		envs := []fakeagent.Envelope{
			execAt(100, "/usr/sbin/sshd", 10),
			execAt(200, "/bin/zsh", 20),
			execAt(300, "/usr/bin/security", 30), // not a shell, must not win
			execAt(400, "/bin/bash", 40),         // latest shell by timestamp
		}
		assert.Equal(t, 400, pickAttackAnchorPID(envs))
	})

	t.Run("most recent by timestamp wins, not file order", func(t *testing.T) {
		t.Parallel()
		// The scrubbed captures are not stored time-sorted: a later line can carry an earlier timestamp. Selection must follow
		// the timestamp, not the file position.
		envs := []fakeagent.Envelope{
			execAt(200, "/bin/zsh", 500),  // later event, earlier in file
			execAt(400, "/bin/bash", 100), // earlier event, later in file
		}
		assert.Equal(t, 200, pickAttackAnchorPID(envs))
	})

	t.Run("sentinel pid is never anchored", func(t *testing.T) {
		t.Parallel()
		envs := []fakeagent.Envelope{exec(1, "/bin/zsh"), exec(0, "/bin/bash")}
		assert.Zero(t, pickAttackAnchorPID(envs))
	})

	t.Run("non-exec events ignored", func(t *testing.T) {
		t.Parallel()
		envs := []fakeagent.Envelope{
			{EventType: "dns_query", Payload: []byte(`{"pid":999}`)},
			exec(200, "/bin/zsh"),
			{EventType: "network_connect", Payload: []byte(`{"pid":888}`)},
		}
		assert.Equal(t, 200, pickAttackAnchorPID(envs))
	})

	t.Run("no shell yields zero", func(t *testing.T) {
		t.Parallel()
		envs := []fakeagent.Envelope{exec(100, "/usr/sbin/sshd"), exec(300, "/usr/bin/security")}
		assert.Zero(t, pickAttackAnchorPID(envs))
	})

	t.Run("malformed payload skipped", func(t *testing.T) {
		t.Parallel()
		envs := []fakeagent.Envelope{{EventType: "exec", Payload: []byte("not json")}, exec(200, "/bin/zsh")}
		assert.Equal(t, 200, pickAttackAnchorPID(envs))
	})
}

// TestReparentAttackToHost confirms the launchd-rooted top of an offset attack subtree is re-pointed at the captured anchor pid,
// while deeper (already-offset) parent links and a missing anchor (<= 1) are left alone.
func TestReparentAttackToHost(t *testing.T) {
	t.Parallel()

	t.Run("launchd-rooted top is re-pointed at the anchor", func(t *testing.T) {
		t.Parallel()
		// Mirrors a scenario after offsetScenarioPIDs: the root fork/exec still reference the pid-1 sentinel; a deeper child keeps
		// its offset parent.
		sc := &fakeagent.Scenario{Timeline: []fakeagent.Event{
			{Type: "fork", ChildPID: 5004555, ParentPID: 1},
			{Type: "exec", PID: 5004555, PPID: 1},
			{Type: "fork", ChildPID: 5004600, ParentPID: 5004555}, // grandchild: parent is the attack root, not launchd
		}}
		reparentAttackToHost(sc, 11439)

		assert.Equal(t, 11439, sc.Timeline[0].ParentPID, "root fork now parented to the captured shell")
		assert.Equal(t, 11439, sc.Timeline[1].PPID, "root exec ppid now the captured shell")
		assert.Equal(t, 5004555, sc.Timeline[2].ParentPID, "deeper parent link untouched")
	})

	t.Run("missing anchor keeps the launchd root", func(t *testing.T) {
		t.Parallel()
		sc := &fakeagent.Scenario{Timeline: []fakeagent.Event{{Type: "exec", PID: 5004555, PPID: 1}}}
		reparentAttackToHost(sc, 0)
		assert.Equal(t, 1, sc.Timeline[0].PPID, "no anchor: attack stays rooted at launchd")
	})
}

// TestManifestCapturesHaveAttackAnchor guards the demo promise that woven attacks nest in a real session: every captured host that
// carries attacks must expose an interactive-shell pid for them to hang off, else they would silently fall back to a lone
// launchd-rooted subtree.
func TestManifestCapturesHaveAttackAnchor(t *testing.T) {
	t.Parallel()
	for _, host := range hostManifest {
		if len(host.Attacks) == 0 {
			continue
		}
		t.Run(host.File, func(t *testing.T) {
			t.Parallel()
			envs, _, err := loadHostEnvelopes(host.File)
			require.NoError(t, err)
			assert.Positive(t, pickAttackAnchorPID(envs), "capture must carry a shell for woven attacks to nest under")
		})
	}
}
