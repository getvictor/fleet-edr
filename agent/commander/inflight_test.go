package commander

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The executor terminalizes a ledger claim it did not win, on the reading that such a claim can only be a crashed prior attempt. That
// reading held while the poll was suspended for as long as the stream was believed up. The poll is now a bounded floor (issue #711),
// so both transports can deliver one command at once, and without the in-flight tracker the loser would report a command FAILED while
// the winner was still running it.
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

	var mu sync.Mutex
	var reported []string
	report := func(_ context.Context, status string, _ json.RawMessage) error {
		mu.Lock()
		defer mu.Unlock()
		reported = append(reported, status)
		return nil
	}

	cmd := Command{ID: 42, HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{"pid":999999}`)}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); push.Execute(t.Context(), cmd, report) }()
	go func() { defer wg.Done(); poll.Execute(t.Context(), cmd, report) }()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	// Assert the MECHANISM, not the outcome. This command's side effect legitimately fails (there is no pid 999999), so "did any
	// report say failed" cannot distinguish a real failure from the spurious one this guards against. What distinguishes them is how
	// many times the command was reported at all: one delivery reports acked then a terminal, whereas the defect adds a second pair
	// from the transport that read the winner's live claim as a crash.
	assert.Len(t, reported, 2, "exactly one transport reports: acked then its terminal outcome, with no second pair from the loser")
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
