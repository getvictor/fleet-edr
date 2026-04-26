package proctable

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateAndLookup(t *testing.T) {
	pt := New()

	pt.Update(100, ProcessInfo{Path: "/usr/bin/ls", UID: 501, StartTime: 1000})

	info, ok := pt.Lookup(100)
	require.True(t, ok, "expected to find PID 100")
	assert.Equal(t, "/usr/bin/ls", info.Path)
	assert.Equal(t, uint32(501), info.UID)
}

func TestRemove(t *testing.T) {
	pt := New()

	pt.Update(200, ProcessInfo{Path: "/usr/bin/cat"})
	pt.Remove(200)

	_, ok := pt.Lookup(200)
	assert.False(t, ok, "expected PID 200 to be removed")
}

func TestRemoveNonexistent(t *testing.T) {
	pt := New()
	pt.Remove(999) // should not panic
}

func TestSize(t *testing.T) {
	pt := New()

	assert.Equal(t, 0, pt.Size())

	pt.Update(1, ProcessInfo{Path: "/bin/sh"})
	pt.Update(2, ProcessInfo{Path: "/bin/bash"})

	assert.Equal(t, 2, pt.Size())

	pt.Remove(1)
	assert.Equal(t, 1, pt.Size())
}

func TestUpdateOverwrites(t *testing.T) {
	pt := New()

	pt.Update(100, ProcessInfo{Path: "/usr/bin/ls"})
	pt.Update(100, ProcessInfo{Path: "/usr/bin/cat"})

	info, ok := pt.Lookup(100)
	require.True(t, ok, "expected to find PID 100")
	assert.Equal(t, "/usr/bin/cat", info.Path)
}

func TestSnapshotIsCopy(t *testing.T) {
	pt := New()
	pt.Update(1, ProcessInfo{Path: "/bin/sh"})
	pt.Update(2, ProcessInfo{Path: "/bin/bash"})

	snap := pt.Snapshot()
	require.Len(t, snap, 2)
	assert.Equal(t, "/bin/sh", snap[1].Path)

	// Mutating the snapshot must not affect the live table.
	snap[3] = ProcessInfo{Path: "/bin/zsh"}
	delete(snap, 1)
	assert.Equal(t, 2, pt.Size(), "snapshot must be independent of the table")
	_, ok := pt.Lookup(1)
	assert.True(t, ok, "table entry must survive snapshot mutation")
	_, ok = pt.Lookup(3)
	assert.False(t, ok, "snapshot insert must not leak into the table")
}

func TestConcurrentAccess(t *testing.T) {
	pt := New()
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := range int32(50) {
		wg.Go(func() {
			pt.Update(i, ProcessInfo{Path: "/bin/test"})
		})
	}

	// Concurrent readers.
	for range 50 {
		wg.Go(func() {
			pt.Size()
			pt.Lookup(1)
		})
	}

	wg.Wait()

	assert.Equal(t, 50, pt.Size())
}
