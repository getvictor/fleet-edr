package gateway

import (
	"context"
	"sync"

	"github.com/fleetdm/edr/internal/control"
)

// sendBuffer bounds the per-connection outbound queue. A control connection carries low-rate async commands (kill, snapshot push), so
// a small buffer is ample; if it ever fills, deliverPending drops the push and the 1s watch re-offers the command next tick, so a slow
// or wedged connection never blocks the watch loop or strands a command.
const sendBuffer = 64

// conn is one live agent control connection. It is the gateway's only per-connection in-process state (ADR-0010 carve-out): the live
// stream's outbound queue, the token used to re-check revocation, the cancel that tears the connection down, and the set of command
// ids currently pushed-but-not-yet-acked (so the watch loop does not re-push a command already in flight). Nothing here is durable;
// losing it forces the agent to reconnect with no command loss because command state lives in MySQL.
type conn struct {
	hostID string
	token  string
	send   chan *control.ServerFrame
	cancel context.CancelFunc

	mu       sync.Mutex
	inflight map[int64]struct{}

	closeOnce sync.Once
}

func newConn(hostID, token string, cancel context.CancelFunc) *conn {
	return &conn{
		hostID:   hostID,
		token:    token,
		send:     make(chan *control.ServerFrame, sendBuffer),
		cancel:   cancel,
		inflight: make(map[int64]struct{}),
	}
}

// close cancels the connection's context exactly once. Cancellation unblocks the writer and maintenance goroutines and makes the
// Connect handler return, which ends the RPC and tears down the stream.
func (c *conn) close() { c.closeOnce.Do(c.cancel) }

// markInflight records that command id is being pushed and reports whether the caller now owns delivery. It returns false when the id
// is already in flight, which is how the fast path and the 1s watch avoid pushing the same command twice within one ack window.
func (c *conn) markInflight(id int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.inflight[id]; ok {
		return false
	}
	c.inflight[id] = struct{}{}
	return true
}

// clearInflight forgets command id, so a later watch tick may re-offer it. Called when an outcome arrives (the command has left the
// pending state and will not be re-queried) and when a push fails to enqueue (so the next tick retries it).
func (c *conn) clearInflight(id int64) {
	c.mu.Lock()
	delete(c.inflight, id)
	c.mu.Unlock()
}

// push enqueues a frame without blocking. It returns false when the buffer is full; the caller clears the in-flight mark so the watch
// loop retries on the next tick rather than blocking on one wedged connection.
func (c *conn) push(frame *control.ServerFrame) bool {
	select {
	case c.send <- frame:
		return true
	default:
		return false
	}
}

// registry maps host id to its single live connection. At most one connection per host: registering a second connection for a host
// evicts the first (returned to the caller to close), preventing a leaked stream and duplicate delivery on reconnect.
type registry struct {
	mu sync.Mutex
	// conns is per-replica perf cache, safe to lose: it holds only live sockets for hosts connected to THIS replica. Losing it (replica
	// restart, gateway stop) just forces those agents to reconnect and fall back to polling; command state lives in MySQL, never here
	// (ADR-0010 control-gateway carve-out).
	conns map[string]*conn
}

func newRegistry() *registry { return &registry{conns: make(map[string]*conn)} }

// add registers c as the connection for its host and returns the prior connection for that host, if any, for the caller to close.
func (r *registry) add(c *conn) *conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.conns[c.hostID]
	r.conns[c.hostID] = c
	return prev
}

// remove deletes the host's connection only if it is still c (a newer connection that already replaced c is left untouched).
func (r *registry) remove(hostID string, c *conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.conns[hostID]; ok && cur == c {
		delete(r.conns, hostID)
	}
}

func (r *registry) get(hostID string) *conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[hostID]
}

// hostIDs snapshots the currently connected hosts for the watch query.
func (r *registry) hostIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.conns))
	for id := range r.conns {
		ids = append(ids, id)
	}
	return ids
}

func (r *registry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// closeAll cancels every live connection so its Connect handler returns. Used on gateway shutdown: cancelling the contexts unblocks
// the long-lived streams (which never end on their own) so the shared HTTP server's graceful shutdown can complete. Entries remove
// themselves from the map via the handler's deferred remove; closeAll only triggers the cancel.
func (r *registry) closeAll() {
	r.mu.Lock()
	conns := make([]*conn, 0, len(r.conns))
	for _, c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()
	for _, c := range conns {
		c.close()
	}
}
