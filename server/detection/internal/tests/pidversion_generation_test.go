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

// forkEvtVer and execEvtVer are the single fork/exec envelope builders for this package. They take an explicit pidversion, nil meaning
// the agent sent none (a pre-#403 agent, or an exec whose audit token was unavailable); forkEvt/execEvt in
// processbatch_differential_test.go delegate here with nil, so there is one wire shape rather than two that can drift apart. The event
// id scheme stays "f"/"e" plus the timestamp so the scenarios that predate pidversion keep the ids they already had.
func forkEvtVer(ts int64, child, parent int, ver *uint32) api.Event {
	return api.Event{EventID: "f" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "fork",
		Payload: json.RawMessage(fmt.Sprintf(`{"child_pid":%d,"parent_pid":%d%s}`, child, parent, verField(ver)))}
}

func execEvtVer(ts int64, pid, ppid int, path string, ver *uint32) api.Event {
	return api.Event{EventID: "e" + strconv.FormatInt(ts, 10), HostID: "x", TimestampNs: ts, IngestedAtNs: ts + 1, EventType: "exec",
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
// spec:server-process-graph-builder/same-pid-re-exec-chain/an-exec-event-without-a-kernel-generation-keeps-the-replaced-one
func TestPIDVersion_ReExecTakesTheExecEventGeneration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// reExecVer is the pidversion on the exec event that replaces the shell's image.
		reExecVer *uint32
		// wantFinal is the pidversion the surviving (curl) generation must carry.
		wantFinal *uint32
		// wantDistinct asserts the two generations of the one pid hold different identities. True only when the replacing exec
		// reported a generation of its own; an event that reported none deliberately keeps the replaced generation's value, so the
		// two rows share it and the distinctness check would contradict the rule under test.
		wantDistinct bool
	}{
		{
			// python3 -c "subprocess.Popen(['/bin/zsh','-c','curl ...'])". zsh execs curl in place, so the payload runs at the
			// shell's pid with no fork boundary, and the row for that image must identify the image, not the shell it replaced.
			name:         "zsh execs curl in place: curl generation carries curl's generation",
			reExecVer:    ptrVer(2379147),
			wantFinal:    ptrVer(2379147),
			wantDistinct: true,
		},
		{
			// A pre-#403 agent, or one whose audit token was unavailable for this exec. The agent's own registry keeps the prior
			// generation in exactly this case, so keeping it here holds the two sides consistent and preserves the PID-reuse pin.
			name:      "exec event carries no generation: row keeps the generation the agent's registry still holds",
			reExecVer: nil,
			wantFinal: ptrVer(2379145),
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
				"the re-exec'd image must carry the generation its own exec event reported, falling back to the generation it "+
					"replaced only when that event reported none")
			assert.Equal(t, shellVer, shell.PIDVersion, "closing a generation must not rewrite the identity it was stored with")
			if tc.wantDistinct {
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
// spec:server-process-graph-builder/same-pid-re-exec-chain/an-exec-event-without-a-kernel-generation-keeps-the-replaced-one
//
// Property: every persisted generation carries the kernel generation in effect for that generation, where "in effect" is the one rule
// all three write paths share. A fork sets the effective generation to whatever the fork reported, including none, because a fork is a
// new identity and inheriting across a pid-reuse boundary would attribute the recycled pid to its predecessor. An exec sets it only
// when the exec reported one, so an exec that reported none leaves the generation it replaced standing. An exit clears it, because a
// later exec on that pid has no live row to inherit from and starts a fresh root.
//
// Stating it as one rule rather than per-path cases is what makes the property worth having: re-exec, first-exec-after-fork,
// exec-without-fork, and pid reuse are all covered by the same assertion, with no branch on the row's chain position. Row counts,
// chain linkage, and pid-reuse closes are covered by the differential and idempotence properties.
//
// The generator walks a monotonic counter the way the kernel does, incrementing on every fork and every exec, over a three-pid space so
// those four shapes collide frequently.
func TestPIDVersion_PersistedGenerationMatchesWireProperty(t *testing.T) {
	t.Parallel()
	b, _, db := twoBuilders(t)
	ctx := t.Context()
	iter := 0

	rapid.Check(t, func(rt *rapid.T) {
		iter++
		host := "pidver-pbt" + strconv.Itoa(iter)

		events, wantAt := drawPIDVersionTimeline(rt)
		require.NoError(t, b.ProcessBatch(ctx, rewriteHost(events, host)))

		for _, r := range dumpNormalizedForest(t, db, ctx, host) {
			// A generation is created either by its fork (still pre-exec) or by its exec, so the instant that identifies it in the
			// model is its exec time when it has one and its fork time otherwise. A re-exec row inherits the original fork time,
			// which is why the exec time has to win here.
			at, kind := r.ForkTimeNs, "forked"
			if r.ExecTimeNs != nil {
				at, kind = *r.ExecTimeNs, "exec'd"
			}
			assert.Equal(rt, wantAt[[2]int64{int64(r.PID), at}], r.PIDVersion, "generation pid %d %s at %d", r.PID, kind, at)
		}
	})
}

// drawPIDVersionTimeline draws a random fork/exec/exit timeline and returns it alongside the expected persisted generation for every
// generation it creates, keyed by (pid, creating event timestamp). Split out from the property body so the generator's draw-and-record
// loop stays readable and under the cognitive-complexity gate.
func drawPIDVersionTimeline(rt *rapid.T) ([]api.Event, map[[2]int64]*uint32) {
	var events []api.Event
	wantAt := map[[2]int64]*uint32{}
	// effective is the generation a new row on that pid would carry right now, per the shared rule described on the property.
	effective := map[int]*uint32{}

	nextVer := uint32(1000)
	ts := int64(1000)
	opCount := rapid.IntRange(1, 14).Draw(rt, "ops")
	for range opCount {
		pid := rapid.IntRange(1, 3).Draw(rt, "pid")
		op := rapid.SampledFrom([]string{"fork", "exec", "exit"}).Draw(rt, "op")
		// A missing pidversion is the legacy-agent shape (or an exec whose audit token was unavailable), drawn often enough to
		// exercise the fall-back paths.
		var ver *uint32
		nextVer++
		if rapid.Bool().Draw(rt, "hasVer") {
			ver = ptrVer(nextVer)
		}
		ts += 100

		switch op {
		case "fork":
			effective[pid] = ver
			events = append(events, forkEvtVer(ts, pid, 1, ver))
		case "exec":
			if ver != nil {
				effective[pid] = ver
			}
			events = append(events, execEvtVer(ts, pid, 1, "/bin/img"+strconv.FormatInt(ts, 10), ver))
		case "exit":
			delete(effective, pid)
			events = append(events, exitEvt(ts, pid, 0))
			continue
		}
		wantAt[[2]int64{int64(pid), ts}] = effective[pid]
	}
	return events, wantAt
}
