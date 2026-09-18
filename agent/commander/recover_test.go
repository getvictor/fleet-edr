package commander

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recoveryServer answers the poll: an empty pending list, the given commands for acked, and it records every status update the agent
// reported back so a test can assert what reached the server rather than what the agent believed it sent.
type recoveryServer struct {
	mu       sync.Mutex
	acked    []Command
	asked    []string
	reported []reportedUpdate
}

type reportedUpdate struct {
	ID     int64
	Status string
	Result string
}

// handler refuses a request it cannot read rather than failing the test from inside it: an assertion here would call FailNow on a
// goroutine that is not the test's, and the tests below assert on the updates they expect, so a refused one shows up as a missing
// update rather than being swallowed.
func (s *recoveryServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body statusUpdate
			id, err := idFromPath(r.URL.Path)
			if err != nil || json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.reported = append(s.reported, reportedUpdate{ID: id, Status: body.Status, Result: string(body.Result)})
			s.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		status := r.URL.Query().Get("status")
		s.mu.Lock()
		s.asked = append(s.asked, status)
		out := []Command{}
		if status == StatusAcked {
			out = s.acked
		}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

func (s *recoveryServer) statusesAsked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

func (s *recoveryServer) updates() []reportedUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]reportedUpdate(nil), s.reported...)
}

// idFromPath reads the command id out of /api/commands/{id}, which is the route the agent reports an outcome on.
func idFromPath(path string) (int64, error) {
	var id int64
	_, err := fmt.Sscanf(path, "/api/commands/%d", &id)
	return id, err
}

// spec:agent-command-executor/the-control-connection-is-preferred-and-polling-is-the-degraded-floor/a-lost-outcome-is-recovered-on-the-polled-path
//
// An outcome the host recorded but could not report is re-reported from the ledger, without the side effect running again. This is
// the gap issue #1080 reported: an acked command is not in the pending answer, so nothing on the poll path would ever ask about it.
func TestRecoverOutcomes_ReReportsWhatTheLedgerRecorded(t *testing.T) {
	t.Parallel()
	server := &recoveryServer{acked: []Command{{ID: 7, HostID: "host-a", CommandType: "kill_process", Status: StatusAcked}}}
	srv := httptest.NewServer(server.handler())
	defer srv.Close()

	ledger := newFakeLedger()
	require.NoError(t, ledger.Mark(t.Context(), 7, StatusCompleted, json.RawMessage(`{"killed":true}`)))
	sender := &recordingExtensionSender{}
	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Ledger: ledger, ExtensionSender: sender}, nil, nil)

	cmdr.recoverOutcomes(t.Context())

	updates := server.updates()
	require.Len(t, updates, 2, "the re-ack and the outcome")
	assert.Equal(t, reportedUpdate{ID: 7, Status: StatusAcked}, updates[0])
	assert.Equal(t, reportedUpdate{ID: 7, Status: StatusCompleted, Result: `{"killed":true}`}, updates[1])
	assert.Empty(t, sender.sent, "the side effect is not run again")
}

// spec:agent-command-executor/the-control-connection-is-preferred-and-polling-is-the-degraded-floor/a-command-the-host-has-no-record-of-is-left-alone
//
// A command the ledger has no record of is left alone. The ledger may have been pruned or replaced, and this path cannot tell that
// from a command that never ran: reporting an outcome would invent one, and running the command would repeat a kill the operator
// asked for once. The server keeps it acked, which is the honest state.
func TestRecoverOutcomes_LeavesACommandTheLedgerDoesNotKnow(t *testing.T) {
	t.Parallel()
	server := &recoveryServer{acked: []Command{{ID: 9, HostID: "host-a", CommandType: "kill_process", Status: StatusAcked}}}
	srv := httptest.NewServer(server.handler())
	defer srv.Close()

	sender := &recordingExtensionSender{}
	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Ledger: newFakeLedger(), ExtensionSender: sender}, nil, nil)

	cmdr.recoverOutcomes(t.Context())

	assert.Empty(t, server.updates(), "nothing is reported for a command this host has no record of")
	assert.Empty(t, sender.sent, "and nothing is executed")
}

// The recovery question runs on its own cadence, not on every poll. The poll is every few seconds and this answer is empty in every
// ordinary case, so asking each time would double a host's request rate for a path that almost never has work.
func TestRecoverOutcomes_AsksOnItsOwnCadence(t *testing.T) {
	t.Parallel()
	server := &recoveryServer{}
	srv := httptest.NewServer(server.handler())
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Ledger: newFakeLedger(), RecoverInterval: time.Hour}, nil, nil)

	cmdr.recoverOutcomes(t.Context())
	cmdr.recoverOutcomes(t.Context())
	cmdr.recoverOutcomes(t.Context())

	assert.Equal(t, []string{StatusAcked}, server.statusesAsked(), "asked once, not once per call")
}

// The first poll after a restart asks, rather than waiting out an interval: an agent that restarted holding an outcome it could not
// deliver is exactly the case this exists for.
func TestRecoverOutcomes_AsksOnTheFirstPoll(t *testing.T) {
	t.Parallel()
	server := &recoveryServer{}
	srv := httptest.NewServer(server.handler())
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Ledger: newFakeLedger(), RecoverInterval: time.Hour}, nil, nil)
	cmdr.pollAndDispatch(t.Context())

	assert.Equal(t, []string{statusPending, StatusAcked}, server.statusesAsked(),
		"the poll asks for new work and for the outcomes the server is still waiting for")
}

// A ledger read that fails reports nothing rather than guessing. The outcome is still on the host and the next pass asks again.
func TestReplayRecorded_AFailedLookupReportsNothing(t *testing.T) {
	t.Parallel()
	server := &recoveryServer{acked: []Command{{ID: 3, HostID: "host-a", CommandType: "kill_process", Status: StatusAcked}}}
	srv := httptest.NewServer(server.handler())
	defer srv.Close()

	ledger := newFakeLedger()
	require.NoError(t, ledger.Mark(t.Context(), 3, StatusCompleted, nil))
	ledger.lookupErr = errContext()
	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Ledger: ledger}, nil, nil)

	cmdr.recoverOutcomes(t.Context())
	assert.Empty(t, server.updates())
}

// A command executing right now in this process is not replayed underneath its own attempt: that attempt reports the outcome, and a
// replay meeting its bare write-ahead claim would report the command failed while it is still running.
func TestReplayRecorded_LeavesACommandThatIsExecuting(t *testing.T) {
	t.Parallel()
	server := &recoveryServer{acked: []Command{{ID: 5, HostID: "host-a", CommandType: "kill_process", Status: StatusAcked}}}
	srv := httptest.NewServer(server.handler())
	defer srv.Close()

	ledger := newFakeLedger()
	require.NoError(t, ledger.seed(5, statusExecuting))
	inFlight := NewInFlight()
	require.True(t, inFlight.Begin(5), "the command is executing in this process")
	defer inFlight.End(5)
	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Ledger: ledger, InFlight: inFlight}, nil, nil)

	cmdr.recoverOutcomes(t.Context())
	assert.Empty(t, server.updates(), "the live attempt reports its own outcome")
}

func errContext() error { return context.DeadlineExceeded }
