package commander

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLedger is an in-memory commander.Ledger for executor unit tests: it gives durable-style dedup (an atomic claim) without SQLite.
type fakeLedger struct {
	mu       sync.Mutex
	m        map[int64]ledgerRow
	claimErr error // when set, Claim returns this error (models a ledger write failure)
}

type ledgerRow struct {
	status string
	result json.RawMessage
}

func newFakeLedger() *fakeLedger { return &fakeLedger{m: make(map[int64]ledgerRow)} }

func (f *fakeLedger) Claim(_ context.Context, id int64, claimStatus string) (bool, string, json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return false, "", nil, f.claimErr
	}
	if r, ok := f.m[id]; ok {
		return false, r.status, r.result, nil
	}
	f.m[id] = ledgerRow{status: claimStatus}
	return true, claimStatus, nil, nil
}

func (f *fakeLedger) Mark(_ context.Context, id int64, status string, result json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = ledgerRow{status: status, result: result}
	return nil
}

func (f *fakeLedger) Delete(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, id)
	return nil
}

// recordReport collects the status transitions an executor reports, so a test can assert the acked-then-terminal sequence.
func recordReport(out *[]string) ReportFunc {
	return func(_ context.Context, status string, _ json.RawMessage) error {
		*out = append(*out, status)
		return nil
	}
}

func killCountingExecutor(ledger Ledger, kills *int) *Executor {
	e := NewExecutor(nil, ledger, nil)
	e.kill = func(int, syscall.Signal) error {
		*kills++
		return nil
	}
	return e
}

// TestExecutor_DedupAcrossExecutors is the core #558 regression: two executors sharing one ledger model the push path and the poll
// path. A kill_process executed by the first must NOT have its side effect re-run by the second (the push-execute -> stream-drop ->
// poll-refetch sequence); the second replays the recorded terminal outcome, so the terminal status stays stable.
//
// spec:agent-command-executor/command-execution-is-deduplicated-durably-across-transports-and-restarts/a-command-executed-on-one-transport-is-not-re-executed-by-the-other
func TestExecutor_DedupAcrossExecutors(t *testing.T) {
	t.Parallel()
	ledger := newFakeLedger()
	var kills int
	cmd := Command{ID: 7, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1234}`)}

	var first []string
	killCountingExecutor(ledger, &kills).Execute(t.Context(), cmd, recordReport(&first))
	require.Equal(t, 1, kills, "the first executor runs the side effect once")
	assert.Equal(t, []string{StatusAcked, StatusCompleted}, first)

	var second []string
	killCountingExecutor(ledger, &kills).Execute(t.Context(), cmd, recordReport(&second))
	assert.Equal(t, 1, kills, "a second executor sharing the ledger does not re-run the side effect")
	assert.Equal(t, []string{StatusAcked, StatusCompleted}, second, "the second executor replays the recorded terminal outcome")
}

// TestExecutor_ReplaysRecordedFailure pins that a recorded terminal failure is replayed verbatim (not retried): a kill that failed
// (e.g. ESRCH) stays failed on re-delivery rather than being re-attempted.
func TestExecutor_ReplaysRecordedFailure(t *testing.T) {
	t.Parallel()
	ledger := newFakeLedger()
	var kills int
	e := NewExecutor(nil, ledger, nil)
	e.kill = func(int, syscall.Signal) error { kills++; return syscall.ESRCH }
	cmd := Command{ID: 8, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":4321}`)}

	var first []string
	e.Execute(t.Context(), cmd, recordReport(&first))
	require.Equal(t, 1, kills)
	assert.Equal(t, []string{StatusAcked, StatusFailed}, first)

	var second []string
	killCountingExecutor(ledger, &kills).Execute(t.Context(), cmd, recordReport(&second))
	assert.Equal(t, 1, kills, "a recorded failure is replayed, not retried")
	assert.Equal(t, []string{StatusAcked, StatusFailed}, second)
}

// TestExecutor_InterruptedClaimNotRetried pins the restart safety: a command claimed (write-ahead "executing") by a prior process that
// then crashed before recording a terminal outcome is NOT re-run; it is terminalized as failed so the server stops re-delivering it and
// the agent never re-signals a possibly-reused PID.
func TestExecutor_InterruptedClaimNotRetried(t *testing.T) {
	t.Parallel()
	ledger := newFakeLedger()
	require.NoError(t, ledger.Mark(t.Context(), 9, statusExecuting, nil)) // a prior, interrupted attempt
	var kills int
	e := killCountingExecutor(ledger, &kills)
	cmd := Command{ID: 9, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1}`)}

	var reports []string
	e.Execute(t.Context(), cmd, recordReport(&reports))
	assert.Equal(t, 0, kills, "an interrupted prior attempt is never re-run")
	assert.Equal(t, []string{StatusAcked, StatusFailed}, reports)
}

// TestExecutor_NoLedgerStillExecutes pins that a nil ledger (tests / degraded path) disables dedup but still runs the command, so the
// executor never hard-depends on the ledger.
func TestExecutor_NoLedgerStillExecutes(t *testing.T) {
	t.Parallel()
	var kills int
	e := killCountingExecutor(nil, &kills)
	var reports []string
	e.Execute(t.Context(), Command{ID: 1, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":2}`)}, recordReport(&reports))
	assert.Equal(t, 1, kills)
	assert.Equal(t, []string{StatusAcked, StatusCompleted}, reports)
}

// TestExecutor_ConcurrentDeliveryRunsSideEffectOnce forces the race the no-concurrency invariant normally prevents: two executors
// sharing one ledger run the same command at the same time. The atomic claim must let only one win, so the privileged side effect
// (kill) runs exactly once even under concurrent delivery (issue #558, CodeRabbit).
//
// spec:agent-command-executor/command-execution-is-deduplicated-durably-across-transports-and-restarts/concurrent-delivery-of-the-same-command-runs-the-side-effect-once
func TestExecutor_ConcurrentDeliveryRunsSideEffectOnce(t *testing.T) {
	t.Parallel()
	ledger := newFakeLedger()
	var kills atomic.Int32
	cmd := Command{ID: 7, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1234}`)}
	mk := func() *Executor {
		e := NewExecutor(nil, ledger, nil)
		e.kill = func(int, syscall.Signal) error { kills.Add(1); return nil }
		return e
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 2 {
		wg.Go(func() {
			<-start
			mk().Execute(t.Context(), cmd, func(context.Context, string, json.RawMessage) error { return nil })
		})
	}
	close(start) // release both goroutines together
	wg.Wait()
	assert.Equal(t, int32(1), kills.Load(), "the side effect runs exactly once even under concurrent delivery")
}

// TestExecutor_ClaimErrorSkipsSideEffect pins that a ledger write failure does NOT fall through to running a non-idempotent side effect
// (issue #558, Copilot/Qodo): without a durable claim the at-most-once guarantee is gone, so the command is left pending instead.
func TestExecutor_ClaimErrorSkipsSideEffect(t *testing.T) {
	t.Parallel()
	ledger := newFakeLedger()
	ledger.claimErr = errors.New("disk full")
	var kills int
	e := killCountingExecutor(ledger, &kills)
	var reports []string
	e.Execute(t.Context(), Command{ID: 5, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1}`)}, recordReport(&reports))
	assert.Equal(t, 0, kills, "a claim that cannot be durably recorded must not run the side effect")
	assert.Empty(t, reports, "the command is left pending for re-dispatch, not reported")
}

// TestExecutor_AckFailureRollsBackClaim pins that when the ack report fails (side effect not started) the write-ahead claim is rolled
// back, so a re-dispatch RE-RUNS the command rather than finding a stranded "executing" row and terminalizing a never-run command.
func TestExecutor_AckFailureRollsBackClaim(t *testing.T) {
	t.Parallel()
	ledger := newFakeLedger()
	var kills int
	e := killCountingExecutor(ledger, &kills)
	cmd := Command{ID: 6, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":1}`)}

	ackFails := func(_ context.Context, status string, _ json.RawMessage) error {
		if status == StatusAcked {
			return errors.New("ack send failed")
		}
		return nil
	}
	e.Execute(t.Context(), cmd, ackFails)
	assert.Equal(t, 0, kills, "the side effect is skipped when the ack fails")

	var reports []string
	e.Execute(t.Context(), cmd, recordReport(&reports))
	assert.Equal(t, 1, kills, "after rollback, a re-dispatch runs the side effect")
	assert.Equal(t, []string{StatusAcked, StatusCompleted}, reports)
}
