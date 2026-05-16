package commander

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestFetchPending401_CallsOnAuthFail locks in the contract that a 401 from the server wakes up the enrollment re-auth hook.
// Regression bar for an early QA bug where a revoked token left the commander silently stuck.
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

// TestExecuteSetApplicationControl_HappyPath covers the set_application_control command path: server enqueues the command, commander
// forwards it to the extension, and reports `completed` with policy_id + policy_version.
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
	// Byte equality, not JSONEq — the commander's contract with the extension is "forward the exact payload bytes the server sent",
	// not "forward some JSON equivalent". Re-marshalling could change field ordering or whitespace and the test must catch that.
	assert.Equal(t, []byte(rawPayload), sender.sent[0],
		"commander must forward the raw payload bytes, not a re-marshalled copy")

	assert.Equal(t, "completed", gotStatus)
	var result map[string]any
	require.NoError(t, json.Unmarshal(gotResult, &result))
	assert.EqualValues(t, 7, result["policy_id"])
	assert.EqualValues(t, 42, result["policy_version"])
}

// TestExecuteSetApplicationControl_InvalidPayload covers the malformed-JSON path: the commander must report `failed` BEFORE handing
// off to XPC so a future schema tightening on the extension side never sees garbage bytes.
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

// TestExecuteSetApplicationControl_InvalidVersion covers the version validation guard: real server versions start at 1, so a zero or
// negative payload version is either a hand-queued test command or an out-of-order delivery and the extension must never see it.
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

// TestExecuteSetApplicationControl_MissingPolicyID covers the symmetric envelope check for policy_id. Zero policy_id never comes from
// a healthy server fan-out; fail explicitly rather than hand garbage to the extension.
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

// TestExecuteSetApplicationControl_RulesMissingOrInvalid covers the envelope check on `rules`. Without this gate, a payload with
// missing or null rules slips past json.Unmarshal-into-json.RawMessage and only fails on the extension's typed decode — but by then
// the commander has already reported `completed`, so the server is wrong about per-host convergence. The commander must reject those
// shapes BEFORE forwarding.
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

// TestExecuteSetApplicationControl_NoSenderConfigured covers the agent startup case where the XPC bridge has not been wired yet (or
// has disconnected). The command must fail with a clear reason so the operator's audit log surfaces "no extension" rather than a
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

// TestUpdateStatus401_CallsOnAuthFail covers the PUT /commands/{id} path — a token can be revoked between fetchPending and the
// following ack/complete, and the hook must fire there too or recovery waits for the next poll tick.
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
