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

func TestConcurrentAccess(t *testing.T) {
	pt := New()
	var wg sync.WaitGroup

	// Concurrent writers.
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pt.Update(int32(i), ProcessInfo{Path: "/bin/test"})
		}()
	}

	// Concurrent readers.
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pt.Size()
			pt.Lookup(1)
		}()
	}

	wg.Wait()

	assert.Equal(t, 50, pt.Size())
}
