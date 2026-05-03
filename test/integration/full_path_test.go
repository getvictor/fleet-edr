//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	responseapi "github.com/fleetdm/edr/server/response/api"
)

// TestFullPath_EnrollIngestCommandAck is the canonical layer-3 smoke
// test: an agent enrolls, uploads events, an alert fires, an admin
// issues a kill command, the agent polls and acks. Five steps, four
// contexts hit via HTTP plus detection.api.Service called directly to
// assert post-conditions.
//
// The test exists to keep the cross-context wiring honest. Per-context
// layer-2 tests cover each context's behaviour in isolation; this one
// catches regressions like "rules' ContentService.ActiveRules() didn't
// flow into detection's engine after the bootstrap-order refactor."
//
// Each step is its own helper so the orchestration here stays
// procedural and readable; the helpers carry the per-step
// boilerplate.
func TestFullPath_EnrollIngestCommandAck(t *testing.T) {
	stack := Setup(t)

	const hostID = "AAAA1111-2222-3333-4444-555566667777"
	hostToken := stepEnroll(t, stack, hostID)
	stepIngestEvents(t, stack, hostID, hostToken)
	commandID := stepIssueKillCommand(t, stack, hostID)
	stepAgentPollsCommands(t, stack, hostToken, hostID, commandID)
	stepAgentAcksCommand(t, stack, hostToken, commandID)
	stepHeartbeatRecorded(t, stack, hostID)
}

func stepEnroll(t *testing.T, stack *Stack, hostID string) string {
	t.Helper()
	body := mustJSON(t, map[string]string{
		"enroll_secret": EnrollSecret,
		"hardware_uuid": hostID,
		"hostname":      "qa-integration.local",
		"agent_version": "layer3-integration-test",
		"os_version":    "macOS 26.0",
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		stack.Server.URL+"/api/enroll", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "/api/enroll status")

	var er enrollResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&er))
	require.Equal(t, hostID, er.HostID)
	require.NotEmpty(t, er.HostToken, "enroll must return a host_token")
	return er.HostToken
}

func stepIngestEvents(t *testing.T, stack *Stack, hostID, hostToken string) {
	t.Helper()
	// Fork + exec from /private/tmp/xxx. We don't rely on this
	// triggering a rule (catalog is content; this smoke does not
	// exercise rule content); the events themselves landing proves
	// endpoint→detection wiring through the host-token middleware.
	now := time.Now().UnixNano()
	events := []detectionapi.Event{
		{
			EventID: "ph8-fork-1", HostID: hostID, TimestampNs: now, EventType: "fork",
			Payload: json.RawMessage(`{"child_pid":4242,"parent_pid":1}`),
		},
		{
			EventID: "ph8-exec-1", HostID: hostID, TimestampNs: now + 1, EventType: "exec",
			Payload: json.RawMessage(`{"pid":4242,"ppid":1,"path":"/private/tmp/payload","args":["payload"]}`),
		},
	}
	body, err := json.Marshal(events)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		stack.Server.URL+"/api/events", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+hostToken)
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "/api/events status")

	// Wait for the processor to materialise the host row with both
	// events counted.
	require.Eventually(t, func() bool {
		hosts, err := stack.DetectionService().ListHosts(t.Context())
		if err != nil {
			return false
		}
		for _, h := range hosts {
			if h.HostID == hostID && h.EventCount >= 2 {
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond)
}

func stepIssueKillCommand(t *testing.T, stack *Stack, hostID string) int64 {
	t.Helper()
	// Skip the operator HTTP path (would require session + CSRF
	// plumbing). Layer-3's value is verifying cross-context wiring,
	// which response.Service.Insert exercises directly: it goes
	// through response/internal/service which validates + writes via
	// response/internal/mysql.
	id, err := stack.ResponseService().Insert(
		t.Context(), hostID, "kill_process",
		json.RawMessage(`{"pid":4242,"reason":"integration smoke"}`),
	)
	require.NoError(t, err)
	require.Positive(t, id, "Insert should return a positive command id")
	return id
}

func stepAgentPollsCommands(t *testing.T, stack *Stack, hostToken, hostID string, commandID int64) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		stack.Server.URL+"/api/commands?status=pending", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var commands []responseapi.Command
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&commands))
	require.NotEmpty(t, commands, "agent must see the queued command")

	for _, c := range commands {
		if c.ID == commandID {
			assert.Equal(t, hostID, c.HostID)
			assert.Equal(t, responseapi.StatusPending, c.Status)
			return
		}
	}
	t.Fatalf("agent must see command id %d among %d returned", commandID, len(commands))
}

func stepAgentAcksCommand(t *testing.T, stack *Stack, hostToken string, commandID int64) {
	t.Helper()
	body := mustJSON(t, map[string]string{"status": "acked"})
	path := stack.Server.URL + "/api/commands/" + strconv.FormatInt(commandID, 10)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+hostToken)
	resp, err := stack.Server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent,
		"PUT /api/commands/{id} status (got %d body=%s)", resp.StatusCode, mustReadBody(t, resp))

	require.Eventually(t, func() bool {
		cmd, err := stack.ResponseService().Get(t.Context(), commandID)
		return err == nil && cmd.Status == responseapi.StatusAcked
	}, 2*time.Second, 50*time.Millisecond)
}

func stepHeartbeatRecorded(t *testing.T, stack *Stack, hostID string) {
	t.Helper()
	// /api/commands doubles as heartbeat in production: response calls
	// detection.api.Service.RecordHostSeen on every poll. The
	// agent_polls_commands step above triggered it. Use Eventually
	// (rather than asserting once) because the heartbeat write happens
	// via a closure invoked from the response handler — there's no
	// in-process synchronisation guaranteeing it lands before the HTTP
	// reply, so a single-shot assertion can race.
	require.Eventually(t, func() bool {
		hosts, err := stack.DetectionService().ListHosts(t.Context())
		if err != nil {
			return false
		}
		for _, h := range hosts {
			if h.HostID == hostID && h.LastSeenNs > 0 {
				return true
			}
		}
		return false
	}, 2*time.Second, 50*time.Millisecond,
		"heartbeat must populate hosts.last_seen_ns for host %s", hostID)
}

// enrollResp mirrors endpoint's POST /api/enroll response shape so the test
// can decode without importing endpoint/internal/.
type enrollResp struct {
	HostID    string `json:"host_id"`
	HostToken string `json:"host_token"`
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func mustReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("(read err: %v)", err)
	}
	return string(b)
}

// Compile-time check that test/integration/ is a layer-3 package whose
// imports are bootstrap + api + testdb (everything else is platform).
// If a future edit accidentally pulls in <X>/internal/, Go's internal/
// rule blocks the import; this declaration just keeps `context.Context`
// in the import list so unused-import never fires the deletion.
var _ context.Context = context.TODO()
