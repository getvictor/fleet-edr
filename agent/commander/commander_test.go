package commander

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spec:agent-command-executor/commands-are-scoped-to-the-authenticated-host/polling-returns-only-this-host-s-commands
//
// Pins the client half of the host-scoping contract: the commander queries /api/commands with its own
// HostID as the host_id query param. The server's response-filtering behavior is the server's
// responsibility (server-admin-surface); the commander's contract is that it MUST query for its own host
// rather than a hard-coded "all" wildcard. If a regression made the commander send no host_id, the server
// would respond with the wrong scope and the per-host audit trail would silently merge.
func TestFetchPending(t *testing.T) {
	commands := []command{
		{ID: 1, HostID: "host-a", CommandType: "kill_process", Payload: json.RawMessage(`{"pid":123}`), Status: "pending"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/commands", r.URL.Path)
		assert.Equal(t, "host-a", r.URL.Query().Get("host_id"))
		assert.Equal(t, "pending", r.URL.Query().Get("status"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(commands)
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	result, err := cmdr.fetchPending(t.Context())
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, int64(1), result[0].ID)
	assert.Equal(t, "kill_process", result[0].CommandType)
}

func TestFetchPendingWithAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", TokenFn: func() string { return "test-key" }}, nil, nil)
	result, err := cmdr.fetchPending(t.Context())
	require.NoError(t, err)
	assert.Empty(t, result)
}

// spec:agent-command-executor/401-during-command-flow-triggers-re-enrollment/401-on-poll
//
// Locks in the contract that a 401 from the server wakes up the enrollment re-auth hook. Regression bar
// for an early QA bug where a revoked token left the commander silently stuck. The scenario also says
// "executor does not treat the 401 as a permanent failure for the next cycle"; that clause is implicit in
// fetchPending returning an error rather than aborting the run loop, exercised by TestRunPolls.
func TestFetchPending401_CallsOnAuthFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer srv.Close()

	var called atomic.Int64
	cmdr := New(Config{
		ServerURL:  srv.URL,
		HostID:     "host-a",
		TokenFn:    func() string { return "stale-token" },
		OnAuthFail: func(context.Context) { called.Add(1) },
	}, nil, nil)

	_, err := cmdr.fetchPending(t.Context())
	require.Error(t, err)
	assert.Equal(t, int64(1), called.Load(), "401 on fetchPending must trigger OnAuthFail exactly once")
}

// recordingApplicationControlSender captures application_control snapshot payloads so tests can inspect them without cgo / real XPC.
// Mimics the production sender's contract: return nil on success, a non-nil error on failure so the commander reports the command as
// `failed`.
type recordingApplicationControlSender struct {
	sent    [][]byte
	sendErr error
}

func (r *recordingApplicationControlSender) SendApplicationControl(payload []byte) error {
	if r.sendErr != nil {
		return r.sendErr
	}
	r.sent = append(r.sent, append([]byte(nil), payload...))
	return nil
}

// spec:agent-command-executor/set-blocklist-command/forwarded-successfully
//
// Covers the set_application_control command path: server enqueues the command, commander forwards it to
// the extension, and reports `completed` with policy_id + policy_version. Note: the spec scenario text
// says "the count of paths in the payload" but the implementation reports policy_id + policy_version; the
// "count of paths" framing predates the set_application_control rename (was originally set_blocklist that
// carried a path list). Filed as #246 to align spec naming.
func TestExecuteSetApplicationControl_HappyPath(t *testing.T) {
	var gotStatus string
	var gotResult []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body statusUpdate
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotStatus = body.Status
		gotResult = body.Result
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender := &recordingApplicationControlSender{}
	c := New(Config{
		ServerURL:                srv.URL,
		HostID:                   "host-a",
		ApplicationControlSender: sender,
	}, nil, nil)

	rawPayload := `{"policy_id":7,"policy_version":42,"rules":[{"rule_type":"BINARY","identifier":"aaa","action":"BLOCK","enforcement":"PROTECT","severity":"medium"}]}`
	cmd := command{
		ID:          11,
		CommandType: "set_application_control",
		Payload:     json.RawMessage(rawPayload),
	}
	c.executeSetApplicationControl(t.Context(), cmd)

	require.Len(t, sender.sent, 1)
	// Byte equality, not JSONEq - the commander's contract with the extension is "forward the exact payload bytes the server sent",
	// not "forward some JSON equivalent". Re-marshalling could change field ordering or whitespace and the test must catch that.
	assert.Equal(t, []byte(rawPayload), sender.sent[0],
		"commander must forward the raw payload bytes, not a re-marshalled copy")

	assert.Equal(t, "completed", gotStatus)
	var result map[string]any
	require.NoError(t, json.Unmarshal(gotResult, &result))
	assert.EqualValues(t, 7, result["policy_id"])
	assert.EqualValues(t, 42, result["policy_version"])
}

// spec:agent-command-executor/set-blocklist-command/payload-is-missing-required-fields-or-has-a-non-positive-version
//
// Covers the malformed-JSON path: the commander must report `failed` BEFORE handing off to XPC so a
// future schema tightening on the extension side never sees garbage bytes. One scenario, four invalid
// shapes pinned by four tests: InvalidPayload (malformed JSON), InvalidVersion (version=0),
// MissingPolicyID (policy_id=0), RulesMissingOrInvalid (rules wrong shape).
func TestExecuteSetApplicationControl_InvalidPayload(t *testing.T) {
	var gotStatus string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body statusUpdate
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotStatus = body.Status
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender := &recordingApplicationControlSender{}
	c := New(Config{ServerURL: srv.URL, HostID: "host-a", ApplicationControlSender: sender}, nil, nil)

	c.executeSetApplicationControl(t.Context(), command{
		ID:          12,
		CommandType: "set_application_control",
		Payload:     json.RawMessage(`{`), // malformed
	})
	assert.Equal(t, "failed", gotStatus)
	assert.Empty(t, sender.sent, "malformed payload must not reach the extension")
}

// spec:agent-command-executor/set-blocklist-command/payload-is-missing-required-fields-or-has-a-non-positive-version
//
// Companion to TestExecuteSetApplicationControl_InvalidPayload: covers the version validation guard. Real
// server versions start at 1, so a zero or negative payload version is either a hand-queued test command
// or an out-of-order delivery and the extension must never see it.
func TestExecuteSetApplicationControl_InvalidVersion(t *testing.T) {
	var gotStatus, gotErr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body statusUpdate
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotStatus = body.Status
		var result map[string]string
		_ = json.Unmarshal(body.Result, &result)
		gotErr = result["error"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender := &recordingApplicationControlSender{}
	c := New(Config{ServerURL: srv.URL, HostID: "host-a", ApplicationControlSender: sender}, nil, nil)

	c.executeSetApplicationControl(t.Context(), command{
		ID:          13,
		CommandType: "set_application_control",
		Payload:     json.RawMessage(`{"policy_id":7,"policy_version":0,"rules":[]}`),
	})
	assert.Equal(t, "failed", gotStatus)
	assert.Equal(t, "invalid policy_version", gotErr)
	assert.Empty(t, sender.sent, "payload with invalid version must not reach the extension")
}

// spec:agent-command-executor/set-blocklist-command/payload-is-missing-required-fields-or-has-a-non-positive-version
//
// Companion to TestExecuteSetApplicationControl_InvalidPayload: symmetric envelope check for policy_id.
// Zero policy_id never comes from a healthy server fan-out; fail explicitly rather than hand garbage to
// the extension.
func TestExecuteSetApplicationControl_MissingPolicyID(t *testing.T) {
	var gotStatus, gotErr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body statusUpdate
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotStatus = body.Status
		var result map[string]string
		_ = json.Unmarshal(body.Result, &result)
		gotErr = result["error"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender := &recordingApplicationControlSender{}
	c := New(Config{ServerURL: srv.URL, HostID: "host-a", ApplicationControlSender: sender}, nil, nil)

	c.executeSetApplicationControl(t.Context(), command{
		ID:          14,
		CommandType: "set_application_control",
		Payload:     json.RawMessage(`{"policy_id":0,"policy_version":1,"rules":[]}`),
	})
	assert.Equal(t, "failed", gotStatus)
	assert.Contains(t, gotErr, "policy_id")
	assert.Empty(t, sender.sent)
}

// spec:agent-command-executor/set-blocklist-command/payload-is-missing-required-fields-or-has-a-non-positive-version
//
// Companion to TestExecuteSetApplicationControl_InvalidPayload: envelope check on `rules`. Without this
// gate, a payload with missing or null rules slips past json.Unmarshal-into-json.RawMessage and only fails
// on the extension's typed decode; but by then the commander has already reported `completed`, so the
// server is wrong about per-host convergence. The commander must reject those shapes BEFORE forwarding.
func TestExecuteSetApplicationControl_RulesMissingOrInvalid(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"missing rules", `{"policy_id":7,"policy_version":1}`},
		{"null rules", `{"policy_id":7,"policy_version":1,"rules":null}`},
		{"rules is object", `{"policy_id":7,"policy_version":1,"rules":{}}`},
		{"rules is string", `{"policy_id":7,"policy_version":1,"rules":"oops"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotStatus, gotErr string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body statusUpdate
				_ = json.NewDecoder(r.Body).Decode(&body)
				gotStatus = body.Status
				var result map[string]string
				_ = json.Unmarshal(body.Result, &result)
				gotErr = result["error"]
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			sender := &recordingApplicationControlSender{}
			c := New(Config{ServerURL: srv.URL, HostID: "host-a", ApplicationControlSender: sender}, nil, nil)
			c.executeSetApplicationControl(t.Context(), command{
				ID:          16,
				CommandType: "set_application_control",
				Payload:     json.RawMessage(tc.payload),
			})
			assert.Equal(t, "failed", gotStatus)
			assert.Contains(t, gotErr, "rules")
			assert.Empty(t, sender.sent, "non-array rules payload must not reach the extension")
		})
	}
}

// TestExecuteSetApplicationControl_EmptyRulesAccepted covers the converse: an empty rules array is a legal state (just-after-policy
// creation, or after every rule is deleted) and the commander must forward it cleanly.
func TestExecuteSetApplicationControl_EmptyRulesAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sender := &recordingApplicationControlSender{}
	c := New(Config{ServerURL: srv.URL, HostID: "host-a", ApplicationControlSender: sender}, nil, nil)
	c.executeSetApplicationControl(t.Context(), command{
		ID:          17,
		CommandType: "set_application_control",
		Payload:     json.RawMessage(`{"policy_id":7,"policy_version":1,"rules":[]}`),
	})
	require.Len(t, sender.sent, 1, "empty rules array is a valid snapshot push")
}

// spec:agent-command-executor/set-blocklist-command/extension-bridge-is-not-available
//
// Covers the agent startup case where the XPC bridge has not been wired yet (or has disconnected). The
// command must fail with a clear reason so the operator's audit log surfaces "no extension" rather than a
// silent success.
func TestExecuteSetApplicationControl_NoSenderConfigured(t *testing.T) {
	var gotStatus string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body statusUpdate
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotStatus = body.Status
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	c.executeSetApplicationControl(t.Context(), command{
		ID:          15,
		CommandType: "set_application_control",
		Payload:     json.RawMessage(`{"policy_id":7,"policy_version":1,"rules":[]}`),
	})
	assert.Equal(t, "failed", gotStatus)
}

// spec:agent-command-executor/401-during-command-flow-triggers-re-enrollment/401-on-status-update
//
// Covers the PUT /commands/{id} path. A token can be revoked between fetchPending and the following
// ack/complete, and the hook must fire there too or recovery waits for the next poll tick.
func TestUpdateStatus401_CallsOnAuthFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var called atomic.Int64
	cmdr := New(Config{
		ServerURL:  srv.URL,
		HostID:     "host-a",
		TokenFn:    func() string { return "stale-token" },
		OnAuthFail: func(context.Context) { called.Add(1) },
	}, nil, nil)

	err := cmdr.updateStatus(t.Context(), 42, "acked", nil)
	require.Error(t, err)
	assert.Equal(t, int64(1), called.Load(), "401 on updateStatus must trigger OnAuthFail exactly once")
}

// spec:agent-command-executor/command-lifecycle-is-explicit/successful-command-transitions
// spec:agent-command-executor/unknown-command-types-fail-explicitly/unknown-command-type
//
// Two scenarios share this test. The unknown-command path is the canonical demonstration of the
// acked-then-terminal transition pattern (the spec scenario for successful-command-transitions allows
// either "completed" or "failed" as the terminal state, both are valid demonstrations); on top of that,
// the test pins the unknown-command-type clause that a `reboot` payload is rejected with a reason
// identifying the unknown type, rather than acked-and-silently-dropped.
func TestDispatchUnknownCommand(t *testing.T) {
	var mu sync.Mutex
	var updates []statusUpdate

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var u statusUpdate
			_ = json.NewDecoder(r.Body).Decode(&u)
			mu.Lock()
			updates = append(updates, u)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	cmd := command{ID: 42, CommandType: "reboot", Payload: json.RawMessage(`{}`)}
	cmdr.dispatch(t.Context(), cmd)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, updates, 2)
	assert.Equal(t, "acked", updates[0].Status)
	assert.Equal(t, "failed", updates[1].Status)
	assert.Contains(t, string(updates[1].Result), "unknown command type")
}

// spec:agent-command-executor/process-termination-command/process-identifier-is-non-positive
//
// pid=0 (or any non-positive identifier) is rejected by the commander before syscall.Kill is ever called,
// and reported as failed with "invalid pid". Pins the guard that prevents the agent from sending SIGKILL
// to pid 0 (which would target the entire process group of the calling process, not what an operator
// asking to kill "the process with id 0" would expect).
func TestDispatchKillInvalidPayload(t *testing.T) {
	var mu sync.Mutex
	var updates []statusUpdate

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var u statusUpdate
			_ = json.NewDecoder(r.Body).Decode(&u)
			mu.Lock()
			updates = append(updates, u)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	cmd := command{ID: 43, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":0}`)}
	cmdr.dispatch(t.Context(), cmd)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, updates, 2)
	assert.Equal(t, "acked", updates[0].Status)
	assert.Equal(t, "failed", updates[1].Status)
	assert.Contains(t, string(updates[1].Result), "invalid pid")
}

// spec:agent-command-executor/polling-cadence-is-configurable/configured-interval-is-honored
// spec:agent-command-executor/polling-cadence-is-configurable/cancellation-between-polls
//
// Two scenarios share this test. The interval clause is pinned by the assertion that with Interval=50ms
// and a 200ms total budget, at least two polls happen (proves the configured cadence is honored rather
// than ignored). The cancellation clause is pinned by Run returning cleanly when the bounding
// context.WithTimeout expires; if cancellation between polls didn't work, Run would not return until the
// inner sleep elapsed and the test would hang past the cleanup deadline.
func TestRunPolls(t *testing.T) {
	var callCount int
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", Interval: 50 * time.Millisecond}, nil, nil)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	_ = cmdr.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	assert.GreaterOrEqual(t, callCount, 2, "should have polled at least twice")
}

// spec:agent-command-executor/command-lifecycle-is-explicit/acknowledgement-fails
//
// Pins the failure-mode of the acked-first contract: if the ack PUT cannot reach the server, the
// commander MUST NOT execute the command's side effects, and the command MUST remain eligible for
// re-dispatch on the next poll. The "remains eligible" half is structural (no completed/failed terminal
// is reported, so the server still sees the command as pending). The test asserts the side effects are
// suppressed by checking that the ApplicationControlSender was never invoked even though the payload was
// valid.
func TestAcknowledgementFailsDoesNotExecute(t *testing.T) {
	var mu sync.Mutex
	var puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			mu.Lock()
			puts++
			mu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sender := &recordingApplicationControlSender{}
	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a", ApplicationControlSender: sender}, nil, nil)
	cmd := command{
		ID:          50,
		CommandType: "set_application_control",
		Payload:     json.RawMessage(`{"policy_id":7,"policy_version":1,"rules":[]}`),
	}
	cmdr.dispatch(t.Context(), cmd)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, puts, "exactly one PUT (the failed acked) must hit the server; no terminal update follows a failed ack")
	assert.Empty(t, sender.sent, "ack failure must short-circuit dispatch BEFORE the extension bridge is invoked")
}

// spec:agent-command-executor/process-termination-command/process-is-already-gone
//
// A kill_process command targeting a PID that is not present in the OS returns ESRCH from syscall.Kill;
// the commander MUST report failed with an error reason that conveys "no such process". 2_147_483_647
// (math.MaxInt32) is an upper-bound PID that no real process will ever hold, giving a portable way to
// induce the not-found path without spawning and reaping a child.
func TestKillProcessAlreadyGone(t *testing.T) {
	var mu sync.Mutex
	var updates []statusUpdate
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var u statusUpdate
			_ = json.NewDecoder(r.Body).Decode(&u)
			mu.Lock()
			updates = append(updates, u)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	// math.MaxInt32 is well outside the pid range any real macOS/Linux process holds.
	cmd := command{ID: 60, CommandType: "kill_process", Payload: json.RawMessage(`{"pid":2147483647}`)}
	cmdr.dispatch(t.Context(), cmd)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, updates, 2)
	assert.Equal(t, "acked", updates[0].Status)
	assert.Equal(t, "failed", updates[1].Status)
	assert.Contains(t, string(updates[1].Result), "no such process",
		"ESRCH must surface as the canonical 'no such process' error reason in the failed result")
}

// spec:agent-command-executor/process-termination-command/successful-kill
//
// Spawns a `sleep 60` child process, dispatches a kill_process command for its PID, and asserts that the
// commander reports completed with killed_pid in the result. The child's cmd.Wait returning a non-nil
// error after the kill is structural (the process was terminated by signal, so Wait returns a
// *exec.ExitError); the spec-relevant clause is the completed-with-killed_pid status the commander
// reports to the server, which is what an operator's audit trail will reflect.
func TestKillProcessSuccessful(t *testing.T) {
	// `sleep` is in coreutils on every macOS and standard Linux runner the EDR CI fleet uses, but a minimal/distroless image might not
	// have it; skip cleanly so the kill_process logic isn't blamed for a missing PATH entry.
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skipf("sleep not on PATH; cannot exercise the real-process kill happy path: %v", err)
	}

	// Bind the child's own context to the test so a stray child cannot outlive the test process; the
	// commander-driven SIGKILL below is what actually reaps it in the happy path.
	childCtx, childCancel := context.WithCancel(t.Context())
	t.Cleanup(childCancel)
	child := exec.CommandContext(childCtx, "sleep", "60")
	require.NoError(t, child.Start(), "spawn sleep child")
	t.Cleanup(func() {
		// Best-effort cleanup: if the test killed the child via the commander, this is a no-op; if the
		// test failed earlier and the child is still running, this prevents a leaked PID.
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	pid := child.Process.Pid

	var mu sync.Mutex
	var updates []statusUpdate
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var u statusUpdate
			_ = json.NewDecoder(r.Body).Decode(&u)
			mu.Lock()
			updates = append(updates, u)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cmdr := New(Config{ServerURL: srv.URL, HostID: "host-a"}, nil, nil)
	payload, err := json.Marshal(map[string]int{"pid": pid})
	require.NoError(t, err)
	cmdr.dispatch(t.Context(), command{ID: 70, CommandType: "kill_process", Payload: payload})

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, updates, 2)
	assert.Equal(t, "acked", updates[0].Status)
	assert.Equal(t, "completed", updates[1].Status)
	var result map[string]int
	require.NoError(t, json.Unmarshal(updates[1].Result, &result))
	assert.Equal(t, pid, result["killed_pid"], "completed result must carry killed_pid identifying the reaped process")
}
