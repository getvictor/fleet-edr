//go:build integration

// Kernel PID generation (pidversion) per process generation. execve increments the generation, so a same-PID re-exec produces an image
// whose identity the closed generation does not share. Measured on macOS 26.6.1: one process execl'ing itself went from pidversion
// 2377919 to 2377920 on the same pid, and a fork-then-exec child went 2401553 (post-fork) to 2401554 (post-exec).
//
// The builder used to inherit the prior generation's value on re-exec, which made every re-exec row carry a stale identity. That is
// worse than carrying none: the agent refuses a kill whose payload names a generation the pid no longer holds, so an operator killing
// a re-exec'd process (every `zsh -c` one-liner, since zsh execs in place) got "process generation mismatch" and nothing died.

package tests

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/detection/api"
)

// forkEvtVer and execEvtVer mirror forkEvt/execEvt from processbatch_differential_test.go with an explicit pidversion, nil meaning the
// agent sent none (a pre-#403 agent, or a flow whose audit token was unavailable). They are separate helpers rather than extra
// parameters on the originals so the existing differential and idempotence scenarios keep their current wire shape.
func forkEvtVer(ts int64, child, parent int, ver *uint32) api.Event {
	return api.Event{EventID: "fv" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "fork",
		Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":%d%s}`, child, parent, verField(ver)))}
}

func execEvtVer(ts int64, pid, ppid int, path string, ver *uint32) api.Event {
	return api.Event{EventID: "ev" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "exec",
		Payload: json.RawMessage(fmt.Sprintf(`{"pid":%d,"ppid":%d,"path":%q,"uid":501,"gid":20%s}`, pid, ppid, path, verField(ver)))}
}

// verField renders the optional pidversion key so a nil draws an envelope with the key absent rather than `"pidversion":null`, which is
// what a pre-#403 agent actually puts on the wire.
func verField(ver *uint32) string {
	if ver == nil {
		return ""
	}
	return fmt.Sprintf(`,"pidversion":%d`, *ver)
}

func ptrVer(v uint32) *uint32 { return &v }

// spec:server-process-graph-builder/same-pid-re-exec-chain/a-re-exec-generation-records-its-own-kernel-generation
// spec:server-process-graph-builder/same-pid-re-exec-chain/an-exec-event-without-a-kernel-generation-records-none
func TestPIDVersion_ReExecTakesTheExecEventGeneration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// reExecVer is the pidversion on the exec event that replaces the shell's image.
		reExecVer *uint32
		// wantFinal is the pidversion the surviving (curl) generation must carry.
		wantFinal *uint32
	}{
		{
			// python3 -c "subprocess.Popen(['/bin/zsh','-c','curl ...'])". zsh execs curl in place, so the payload runs at the
			// shell's pid with no fork boundary, and the row for that image must identify the image, not the shell it replaced.
			name:      "zsh execs curl in place: curl generation carries curl's generation",
			reExecVer: ptrVer(2379147),
			wantFinal: ptrVer(2379147),
		},
		{
			name:      "exec event carries no generation: row records none rather than inheriting the shell's",
			reExecVer: nil,
			wantFinal: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, _, db := twoBuilders(t)
			ctx := t.Context()
			host := "reexec-" + t.Name()

			const pythonPID, shellPID = 500, 600
			shellVer := ptrVer(2379145)
			events := rewriteHost([]api.Event{
				forkEvtVer(1000, pythonPID, 1, ptrVer(2379143)),
				execEvtVer(1100, pythonPID, 1, "/opt/homebrew/bin/python3", ptrVer(2379144)),
				forkEvtVer(2000, shellPID, pythonPID, ptrVer(2379146)),
				execEvtVer(2100, shellPID, pythonPID, "/bin/zsh", shellVer),
				execEvtVer(3000, shellPID, pythonPID, "/usr/bin/curl", tc.reExecVer),
			}, host)
			require.NoError(t, b.ProcessBatch(ctx, events))

			rows := dumpNormalizedForest(t, db, ctx, host)
			shell, curl := generationAt(t, rows, shellPID, 2100), generationAt(t, rows, shellPID, 3000)

			assert.Equal(t, tc.wantFinal, curl.PIDVersion,
				"the re-exec'd image must carry its own exec event's generation, never the generation it replaced")
			assert.Equal(t, shellVer, shell.PIDVersion, "closing a generation must not rewrite the identity it was stored with")
			if tc.wantFinal != nil {
				assert.NotEqual(t, *shellVer, *curl.PIDVersion, "the two generations of one pid must not share an identity")
			}
		})
	}
}

// generationAt returns the single row for pid whose exec_time_ns is execTs, failing the test when the generation is missing or
// ambiguous. Keying on the exec instant identifies a generation without depending on row ids or on the ordering the builder happens to
// flush in.
func generationAt(t *testing.T, rows []normRow, pid int, execTs int64) normRow {
	t.Helper()
	var found []normRow
	for _, r := range rows {
		if r.PID == pid && r.ExecTimeNs != nil && *r.ExecTimeNs == execTs {
			found = append(found, r)
		}
	}
	require.Len(t, found, 1, "expected exactly one generation for pid %d exec'd at %d", pid, execTs)
	return found[0]
}

// spec:server-process-graph-builder/same-pid-re-exec-chain/a-re-exec-generation-records-its-own-kernel-generation
//
// Property: every persisted generation carries the kernel generation that the wire reported for THAT generation. The assertion is
// stated against the drawn events rather than against a model of the row lifecycle, so it cannot pass or fail for reasons unrelated to
// pidversion (row counts, chain linkage, and pid-reuse closes are covered by the differential and idempotence properties).
//
// The generator walks a monotonic counter the way the kernel does, incrementing on every fork and every exec, over a three-pid space so
// re-exec, pid reuse, and exec-without-fork collide frequently.
func TestPIDVersion_PersistedGenerationMatchesWireProperty(t *testing.T) {
	t.Parallel()
	b, _, db := twoBuilders(t)
	ctx := t.Context()
	iter := 0

	rapid.Check(t, func(rt *rapid.T) {
		iter++
		host := "pidver-pbt" + strconv.Itoa(iter)

		var events []api.Event
		// execVerAt and forkVerAt record what the wire carried, keyed by (pid, event timestamp). Absent means "the event carried no
		// pidversion", which the fork/exec handlers must persist as NULL rather than borrowing a neighbouring value.
		execVerAt := map[[2]int64]*uint32{}
		forkVerAt := map[[2]int64]*uint32{}

		nextVer := uint32(1000)
		ts := int64(1000)
		opCount := rapid.IntRange(1, 14).Draw(rt, "ops")
		for range opCount {
			pid := rapid.IntRange(1, 3).Draw(rt, "pid")
			op := rapid.SampledFrom([]string{"fork", "exec", "exit"}).Draw(rt, "op")
			// A missing pidversion is the legacy-agent shape, drawn often enough to exercise the NULL paths.
			var ver *uint32
			nextVer++
			if rapid.Bool().Draw(rt, "hasVer") {
				ver = ptrVer(nextVer)
			}
			ts += 100

			switch op {
			case "fork":
				events = append(events, forkEvtVer(ts, pid, 1, ver))
				forkVerAt[[2]int64{int64(pid), ts}] = ver
			case "exec":
				events = append(events, execEvtVer(ts, pid, 1, "/bin/img"+strconv.FormatInt(ts, 10), ver))
				execVerAt[[2]int64{int64(pid), ts}] = ver
			case "exit":
				events = append(events, exitEvt(ts, pid, 0))
			}
		}

		require.NoError(t, b.ProcessBatch(ctx, rewriteHost(events, host)))

		for _, r := range dumpNormalizedForest(t, db, ctx, host) {
			key := [2]int64{int64(r.PID), r.ForkTimeNs}
			if r.ExecTimeNs == nil {
				// A forked-but-not-yet-exec'd generation keeps the child generation the fork reported.
				assert.Equal(rt, forkVerAt[key], r.PIDVersion, "pre-exec generation pid %d forked at %d", r.PID, r.ForkTimeNs)
				continue
			}
			want := execVerAt[[2]int64{int64(r.PID), *r.ExecTimeNs}]
			// A re-exec generation is the one carrying a back-reference to the image it replaced. It is INSERTed, so an exec that
			// reported no pidversion leaves it NULL: inheriting the replaced generation's value is the bug this property pins.
			// The first exec after a fork has no back-reference and UPDATEs its fork row through COALESCE instead, so there an
			// absent value leaves the fork's own value standing rather than clobbering it.
			if want == nil && r.PrevRank == -1 {
				want = forkVerAt[key]
			}
			assert.Equal(rt, want, r.PIDVersion, "generation pid %d exec'd at %d", r.PID, *r.ExecTimeNs)
		}
	})
}
