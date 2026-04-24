package processttl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReconciler struct {
	calls      []call
	fixedN     int64
	forceError error
	callCount  atomic.Int64 // goroutine-safe counter for Loop tests
}

type call struct {
	cutoffNs int64
	maxAgeNs int64
}

func (f *fakeReconciler) ReconcileStaleProcesses(_ context.Context, cutoffNs, maxAgeNs int64) (int64, error) {
	f.calls = append(f.calls, call{cutoffNs: cutoffNs, maxAgeNs: maxAgeNs})
	f.callCount.Add(1)
	if f.forceError != nil {
		return 0, f.forceError
	}
	return f.fixedN, nil
}

type fakeMetrics struct {
	total int64
}

func (m *fakeMetrics) ProcessesTTLReconciled(_ context.Context, n int64) {
	m.total += n
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunner_Run_PassesCorrectCutoff(t *testing.T) {
	fake := &fakeReconciler{fixedN: 7}
	fixedNow := time.Unix(1_700_000_000, 0).UTC()

	r := New(fake, Options{
		MaxAge:  6 * time.Hour,
		Logger:  quietLogger(),
		Now:     func() time.Time { return fixedNow },
		Metrics: &fakeMetrics{},
	})

	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(7), n)

	require.Len(t, fake.calls, 1)
	c := fake.calls[0]
	assert.Equal(t, fixedNow.UnixNano()-(6*time.Hour).Nanoseconds(), c.cutoffNs)
	assert.Equal(t, (6 * time.Hour).Nanoseconds(), c.maxAgeNs)
}

func TestRunner_Run_DisabledWhenMaxAgeZero(t *testing.T) {
	fake := &fakeReconciler{fixedN: 100}
	r := New(fake, Options{MaxAge: 0, Logger: quietLogger()})

	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
	assert.Empty(t, fake.calls)
}

func TestRunner_Run_RecordsMetric(t *testing.T) {
	fake := &fakeReconciler{fixedN: 3}
	m := &fakeMetrics{}
	r := New(fake, Options{
		MaxAge:  time.Hour,
		Logger:  quietLogger(),
		Metrics: m,
	})

	_, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(3), m.total)
}

func TestRunner_Run_PropagatesStoreError(t *testing.T) {
	boom := errors.New("db dropped the table")
	fake := &fakeReconciler{forceError: boom}
	r := New(fake, Options{MaxAge: time.Hour, Logger: quietLogger()})

	_, err := r.Run(t.Context())
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

func TestRunner_NewPanicsOnNilStore(t *testing.T) {
	assert.Panics(t, func() {
		_ = New(nil, Options{MaxAge: time.Hour})
	})
}

func TestRunner_Loop_SkipsWhenDisabled(t *testing.T) {
	fake := &fakeReconciler{}
	r := New(fake, Options{MaxAge: 0, Logger: quietLogger()})

	// Disabled runner (MaxAge == 0) should return immediately without ever
	// calling the store.
	done := make(chan struct{})
	go func() {
		r.Loop(t.Context())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("disabled Loop didn't return promptly")
	}
	assert.Empty(t, fake.calls)
}

func TestRunner_Loop_ExitsOnCtxCancel(t *testing.T) {
	fake := &fakeReconciler{}
	r := New(fake, Options{
		MaxAge:   time.Hour,
		Interval: 10 * time.Millisecond,
		Logger:   quietLogger(),
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		r.Loop(ctx)
		close(done)
	}()

	// Wait for the immediate first-run to land before cancelling so we prove
	// the loop was actually active, not just blocked at the disabled guard.
	require.Eventually(t, func() bool { return fake.callCount.Load() >= 1 },
		2*time.Second, 5*time.Millisecond, "Loop's initial run should fire")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not exit after ctx cancel")
	}
}
