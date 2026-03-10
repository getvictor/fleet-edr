// Package proctable provides an in-memory PID-to-process lookup table.
// It is populated from ESF exec events and cleared on exit events, allowing
// the agent to enrich network events with process metadata.
package proctable

import "sync"

// ProcessInfo holds metadata about a running process.
type ProcessInfo struct {
	Path      string
	UID       uint32
	StartTime int64 // timestamp_ns from the exec/fork event
}

// Table is a thread-safe mapping from PID to process metadata.
type Table struct {
	mu      sync.RWMutex
	entries map[int32]ProcessInfo
}

// New creates an empty process table.
func New() *Table {
	return &Table{
		entries: make(map[int32]ProcessInfo),
	}
}

// Update inserts or replaces the entry for the given PID.
func (t *Table) Update(pid int32, info ProcessInfo) {
	t.mu.Lock()
	t.entries[pid] = info
	t.mu.Unlock()
}

// Lookup returns the process info for the given PID, if present.
func (t *Table) Lookup(pid int32) (ProcessInfo, bool) {
	t.mu.RLock()
	info, ok := t.entries[pid]
	t.mu.RUnlock()
	return info, ok
}

// Remove deletes the entry for the given PID.
func (t *Table) Remove(pid int32) {
	t.mu.Lock()
	delete(t.entries, pid)
	t.mu.Unlock()
}

// Size returns the number of tracked processes.
func (t *Table) Size() int {
	t.mu.RLock()
	n := len(t.entries)
	t.mu.RUnlock()
	return n
}
