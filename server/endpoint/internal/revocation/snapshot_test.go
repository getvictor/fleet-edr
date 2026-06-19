package revocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct {
	entries []Entry
	err     error
	calls   int
}

func (f *fakeSource) RevocationEntries(context.Context) ([]Entry, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

func TestSnapshot_Allowed(t *testing.T) {
	t.Parallel()
	src := &fakeSource{entries: []Entry{
		{HostID: "revoked-host", Revoked: true, Epoch: 0},
		{HostID: "cycled-host", Revoked: false, Epoch: 2},
	}}
	s := NewSnapshot(src, nil)
	require.NoError(t, s.Refresh(t.Context()))

	cases := []struct {
		name       string
		hostID     string
		tokenEpoch int64
		want       bool
	}{
		{"absent host allowed", "unknown-host", 0, true},
		{"revoked host denied at any epoch", "revoked-host", 99, false},
		{"cycled host denied below current epoch", "cycled-host", 1, false},
		{"cycled host allowed at current epoch", "cycled-host", 2, true},
		{"cycled host allowed above current epoch", "cycled-host", 3, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, s.Allowed(tc.hostID, tc.tokenEpoch))
		})
	}
}

func TestSnapshot_Size(t *testing.T) {
	t.Parallel()
	src := &fakeSource{entries: []Entry{{HostID: "a", Revoked: true}, {HostID: "b", Epoch: 1}}}
	s := NewSnapshot(src, nil)
	assert.Equal(t, 0, s.Size(), "empty before first refresh")
	require.NoError(t, s.Refresh(t.Context()))
	assert.Equal(t, 2, s.Size())
}

func TestNewSnapshot_NilSource_Panics(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { NewSnapshot(nil, nil) })
}

func TestSnapshot_Run_RefreshesThenStops(t *testing.T) {
	t.Parallel()
	src := &fakeSource{entries: []Entry{{HostID: "revoked-host", Revoked: true}}}
	s := NewSnapshot(src, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx, 50*time.Millisecond); close(done) }()
	// Run performs an immediate refresh on entry, so the revoked host becomes visible without waiting for the first tick.
	require.Eventually(t, func() bool { return s.Size() == 1 }, time.Second, 10*time.Millisecond)
	assert.False(t, s.Allowed("revoked-host", 0))
	cancel()
	<-done
}

func TestSnapshot_Forget(t *testing.T) {
	t.Parallel()
	src := &fakeSource{entries: []Entry{{HostID: "h", Revoked: true}}}
	s := NewSnapshot(src, nil)
	require.NoError(t, s.Refresh(t.Context()))
	assert.False(t, s.Allowed("h", 0))
	s.Forget("h")
	assert.True(t, s.Allowed("h", 0), "forgotten host is allowed without waiting for a refresh")
	assert.Equal(t, 0, s.Size())
}

// spec:agent-enrollment/revocation-is-enforced-by-a-per-replica-snapshot/snapshot-refresh-failure-retains-the-previous-view
func TestSnapshot_Refresh_ErrorRetainsPrevious(t *testing.T) {
	t.Parallel()
	src := &fakeSource{entries: []Entry{{HostID: "revoked-host", Revoked: true}}}
	s := NewSnapshot(src, nil)
	require.NoError(t, s.Refresh(t.Context()))
	assert.False(t, s.Allowed("revoked-host", 0))

	// A failing refresh must not drop the previous snapshot (which would briefly un-revoke the host).
	src.err = errors.New("db down")
	require.Error(t, s.Refresh(t.Context()))
	assert.False(t, s.Allowed("revoked-host", 0), "previous snapshot retained on refresh error")
}
