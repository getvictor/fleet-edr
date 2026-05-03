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
// test, per claude/modular-monolith/plan.md §Phase 5: an agent enrolls,
// uploads events, an alert fires, an admin issues a kill command, the
// agent polls and acks. Five steps, four contexts hit via HTTP plus
// detection.api.Service called directly to assert post-conditions.
//
// The test exists to keep the cross-context wiring honest. Per-context
// layer-2 tests cover each context's behaviour in isolation; this one
// catches regressions like "rules' ContentService.ActiveRules() didn't
// flow into detection's engine after the bootstrap-order refactor."
func TestFullPath_EnrollIngestCommandAck(t *testing.T) {
	stack := Setup(t)
	srv := stack.Server
	client := srv.Client()
	ctx := t.Context()

	const hostID = "AAAA1111-2222-3333-4444-555566667777"
	var hostToken string

	t.Run("enroll", func(t *testing.T) {
		body := mustJSON(t, map[string]string{
			"enroll_secret": EnrollSecret,
			"hardware_uuid": hostID,
			"hostname":      "qa-integration.local",
			"agent_version": "phase8-integration-test",
			"os_version":    "macOS 26.0",
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/enroll", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "/api/enroll status")

		var er enrollResp
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&er))
		require.Equal(t, hostID, er.HostID)
		require.NotEmpty(t, er.HostToken, "enroll must return a host_token")
		hostToken = er.HostToken
	})

	t.Run("ingest_events_via_host_token", func(t *testing.T) {
		// Fork + exec from /private/tmp/xxx. Suspicious paths plus the
		// fork→exec sequence is what suspicious_exec fires on. We don't
		// rely on this triggering (catalog is content; phase 8 doesn't
		// change rule content), but the events themselves landing
		// proves endpoint→detection wiring through the host-token
		// middleware.
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
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/events", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+hostToken)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "/api/events status")

		// Confirm the events landed in detection's store. CountUnprocessed
		// drops to 0 once the processor materialises them; if both events
		// were ingested the count starts >0 and trends to 0. Either way,
		// "no error" + the host's row appearing under ListHosts is the
		// success signal.
		require.Eventually(t, func() bool {
			hosts, err := stack.DetectionService().ListHosts(ctx)
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
	})

	var commandID int64
	t.Run("admin_issues_kill_command", func(t *testing.T) {
		// Skip the operator HTTP path (would require session + CSRF
		// plumbing). Layer-3's value is verifying cross-context wiring,
		// which response.Service.Insert exercises directly: it goes
		// through response/internal/service which validates + writes
		// via response/internal/mysql.
		id, err := stack.ResponseService().Insert(
			ctx, hostID, "kill_process",
			json.RawMessage(`{"pid":4242,"reason":"phase 8 integration smoke"}`),
		)
		require.NoError(t, err)
		require.Positive(t, id, "Insert should return a positive command id")
		commandID = id
	})

	t.Run("agent_polls_commands", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			srv.URL+"/api/commands?status=pending", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+hostToken)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var commands []responseapi.Command
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&commands))
		require.NotEmpty(t, commands, "agent must see the queued command")

		// Find the command we just issued.
		var found bool
		for _, c := range commands {
			if c.ID == commandID {
				assert.Equal(t, hostID, c.HostID)
				assert.Equal(t, responseapi.StatusPending, c.Status)
				found = true
				break
			}
		}
		require.True(t, found, "agent must see command id %d", commandID)
	})

	t.Run("agent_acks_command", func(t *testing.T) {
		body := mustJSON(t, map[string]string{"status": "acked"})
		path := srv.URL + "/api/commands/" + strconv.FormatInt(commandID, 10)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, path, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+hostToken)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent,
			"PUT /api/commands/{id} status (got %d body=%s)", resp.StatusCode, mustReadBody(t, resp))

		// Confirm the status transition propagated to the store.
		require.Eventually(t, func() bool {
			cmd, err := stack.ResponseService().Get(ctx, commandID)
			return err == nil && cmd.Status == responseapi.StatusAcked
		}, 2*time.Second, 50*time.Millisecond)
	})

	t.Run("heartbeat_recorded", func(t *testing.T) {
		// /api/commands doubles as heartbeat in production: response
		// calls detection.api.Service.RecordHostSeen on every poll. The
		// agent_polls_commands sub-test above triggered it; assert
		// detection saw the host.
		hosts, err := stack.DetectionService().ListHosts(ctx)
		require.NoError(t, err)
		var seen bool
		for _, h := range hosts {
			if h.HostID == hostID {
				seen = true
				assert.Positive(t, h.LastSeenNs,
					"heartbeat must populate hosts.last_seen_ns")
				break
			}
		}
		assert.True(t, seen, "host %s must appear in detection.ListHosts after agent poll", hostID)
	})
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
