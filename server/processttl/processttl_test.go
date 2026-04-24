package processttl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReconciler struct {
	calls      []call
	fixedN     int64
	forceError error
}

type call struct {
	cutoffNs int64
	maxAgeNs int64
}

func (f *fakeReconciler) ReconcileStaleProcesses(_ context.Context, cutoffNs, maxAgeNs int64) (int64, error) {
	f.calls = append(f.calls, call{cutoffNs: cutoffNs, maxAgeNs: maxAgeNs})
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

func TestRunner_Loop_ExitsOnCtxCancelAndSkipsWhenDisabled(t *testing.T) {
	fake := &fakeReconciler{}
	r := New(fake, Options{MaxAge: 0, Logger: quietLogger()})

	// Disabled runner should return immediately even without cancelling ctx,
	// because Loop's first branch handles the no-op case.
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
