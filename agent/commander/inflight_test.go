package commander

import (
	"context"
	"encoding/json"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The executor terminalizes a ledger claim it did not win, on the reading that such a claim can only be a crashed prior attempt. That
// reading held while the poll was suspended for as long as the stream was believed up. The poll is now a bounded floor (issue #711),
// so both transports can deliver one command AT THE SAME TIME, and without the in-flight tracker the loser would read the winner's
// live claim as a crash and report a running command failed.
//
// The overlap is forced rather than raced for. Two goroutines calling Execute usually do not overlap, and when they do not the second
// delivery legitimately REPLAYS the recorded terminal outcome, which is correct behaviour and looks nothing like the defect. Blocking
// the winner inside its side effect is what makes the concurrent case the one under test every run.
//
// spec:agent-control-channel/the-connection-detects-and-recovers-from-silent-failure/both-transports-deliver-one-command-at-the-same-time
func TestBothTransportsDeliveringOneCommandRunItOnceAndReportNoFailure(t *testing.T) {
	t.Parallel()

	ledger := newFakeLedger()
	shared := NewInFlight()

	// Two executors, as in production: the commander builds one and the control client builds another. They share the ledger and the
	// in-flight tracker and nothing else.
	push := NewExecutor(nil, ledger, nil)
	push.SetInFlight(shared)
	poll := NewExecutor(nil, ledger, nil)
	poll.SetInFlight(shared)

	inSideEffect := make(chan struct{})
	release := make(chan struct{})
	push.kill = func(int, syscall.Signal) error {
		close(inSideEffect)
		<-release
		return nil
	}
	poll.kill = func(int, syscall.Signal) error { return nil }

	var mu sync.Mutex
	reported := map[string][]string{}
	report := func(who string) ReportFunc {
		return func(_ context.Context, status string, _ json.RawMessage) error {
			mu.Lock()
			defer mu.Unlock()
			reported[who] = append(reported[who], status)
			return nil
		}
	}

	cmd := Command{ID: 42, HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{"pid":4242}`)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		push.Execute(t.Context(), cmd, report("push"))
	}()
	<-inSideEffect // the winner is now provably mid-execution, holding both the ledger claim and the in-flight entry

	poll.Execute(t.Context(), cmd, report("poll"))

	close(release)
	<-done

	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, reported["poll"],
		"the transport that arrives while the other is executing must report nothing, not read the live claim as a crash")
	assert.Equal(t, []string{StatusAcked, StatusCompleted}, reported["push"], "the transport that owns it reports its own lifecycle")
	assert.Equal(t, 1, ledger.claims(42), "the command is claimed once, so the side effect runs at most once")
}

// A claim left by a CRASH must still be terminalized, which is the behaviour the tracker has to preserve: liveness is process-local,
// so a claim written by a process that has since died cannot appear in this process's tracker.
// spec:agent-control-channel/the-connection-detects-and-recovers-from-silent-failure/an-execution-claim-left-by-a-crash-is-still-resolved
func TestAClaimLeftByACrashIsStillTerminalized(t *testing.T) {
	t.Parallel()

	ledger := newFakeLedger()
	// A prior process claimed and died: the ledger holds "executing" with no terminal outcome, and nothing is in flight here.
	require.NoError(t, ledger.seed(42, statusExecuting))

	exec := NewExecutor(nil, ledger, nil)
	exec.SetInFlight(NewInFlight())

	var reported []string
	report := func(_ context.Context, status string, _ json.RawMessage) error {
		reported = append(reported, status)
		return nil
	}
	exec.Execute(t.Context(), Command{ID: 42, HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1}`)}, report)

	assert.Contains(t, reported, StatusFailed, "an interrupted attempt is still terminalized so the server stops re-delivering")
}
