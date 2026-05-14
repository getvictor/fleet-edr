package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestApplicationControlBlock_TableDriven covers every branch of the
// block-event-to-finding mapping: happy path, missing fields, missing
// process row, malformed payload, and the custom_msg default. Each
// case names the property under test rather than the input; a failure
// here pinpoints the exact mapping invariant that broke.
func TestApplicationControlBlock_TableDriven(t *testing.T) {
	customMsg := "Blocked: Calculator is not allowed"
	cases := []struct {
		name         string
		payload      map[string]any
		eventType    string
		procExists   bool
		wantFindings int
		wantSeverity string
		wantTitle    string
		wantDesc     string
		wantSource   string
		wantRuleID   string
	}{
		{
			name:      "happy path produces application_control finding",
			eventType: "application_control_block",
			payload: map[string]any{
				"pid":            int64(100),
				"path":           "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
				"rule_id":        "app_control:42",
				"rule_type":      "BINARY",
				"identifier":     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"severity":       "high",
				"custom_msg":     customMsg,
				"policy_id":      int64(11),
				"policy_version": int64(3),
			},
			procExists:   true,
			wantFindings: 1,
			wantSeverity: "high",
			wantTitle:    "Application blocked: Calculator",
			wantDesc:     customMsg,
			wantSource:   api.AlertSourceApplicationControl,
			wantRuleID:   "app_control:42",
		},
		{
			name:      "missing custom_msg falls back to deterministic default",
			eventType: "application_control_block",
			payload: map[string]any{
				"pid":            int64(100),
				"path":           "/bin/ls",
				"rule_id":        "app_control:7",
				"rule_type":      "BINARY",
				"identifier":     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"severity":       "medium",
				"policy_id":      int64(11),
				"policy_version": int64(3),
			},
			procExists:   true,
			wantFindings: 1,
			wantSeverity: "medium",
			wantTitle:    "Application blocked: ls",
			wantDesc:     "Blocked BINARY rule for bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			wantSource:   api.AlertSourceApplicationControl,
			wantRuleID:   "app_control:7",
		},
		{
			name:      "wrong event type is ignored",
			eventType: "exec",
			payload: map[string]any{
				"pid":            int64(100),
				"rule_id":        "app_control:1",
				"severity":       "high",
				"path":           "/bin/ls",
				"rule_type":      "BINARY",
				"identifier":     "x",
				"policy_id":      int64(1),
				"policy_version": int64(1),
			},
			procExists:   true,
			wantFindings: 0,
		},
		{
			name:      "missing rule_id skips event",
			eventType: "application_control_block",
			payload: map[string]any{
				"pid":            int64(100),
				"path":           "/bin/ls",
				"rule_type":      "BINARY",
				"identifier":     "x",
				"severity":       "high",
				"policy_id":      int64(1),
				"policy_version": int64(1),
			},
			procExists:   true,
			wantFindings: 0,
		},
		{
			name:      "missing severity skips event",
			eventType: "application_control_block",
			payload: map[string]any{
				"pid":            int64(100),
				"path":           "/bin/ls",
				"rule_id":        "app_control:1",
				"rule_type":      "BINARY",
				"identifier":     "x",
				"policy_id":      int64(1),
				"policy_version": int64(1),
			},
			procExists:   true,
			wantFindings: 0,
		},
		{
			name:      "missing process row skips event",
			eventType: "application_control_block",
			payload: map[string]any{
				"pid":            int64(999),
				"path":           "/bin/ls",
				"rule_id":        "app_control:1",
				"rule_type":      "BINARY",
				"identifier":     "x",
				"severity":       "high",
				"policy_id":      int64(1),
				"policy_version": int64(1),
			},
			procExists:   false,
			wantFindings: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := &ApplicationControlBlock{}
			payload, err := json.Marshal(tc.payload)
			require.NoError(t, err)
			gr := &stubBlockGraphReader{exists: tc.procExists, procID: 99}

			findings, err := rule.Evaluate(t.Context(), []api.Event{{
				EventID:     "evt-1",
				HostID:      "host-a",
				TimestampNs: 1000,
				EventType:   tc.eventType,
				Payload:     payload,
			}}, gr)
			require.NoError(t, err)
			require.Len(t, findings, tc.wantFindings)
			if tc.wantFindings == 0 {
				return
			}
			got := findings[0]
			assert.Equal(t, tc.wantRuleID, got.RuleID)
			assert.Equal(t, tc.wantSource, got.Source)
			assert.Equal(t, tc.wantSeverity, got.Severity)
			assert.Equal(t, tc.wantTitle, got.Title)
			assert.Equal(t, tc.wantDesc, got.Description)
			assert.Equal(t, int64(99), got.ProcessID)
			assert.Equal(t, []string{"evt-1"}, got.EventIDs)
		})
	}
}

// TestApplicationControlBlock_GraphReaderError surfaces the
// distinct failure mode where the GraphReader itself returns an
// error (DB unreachable, query timeout). The rule must propagate
// that error so the processor can unclaim + retry the batch instead
// of silently dropping the block.
func TestApplicationControlBlock_GraphReaderError(t *testing.T) {
	rule := &ApplicationControlBlock{}
	payload, err := json.Marshal(map[string]any{
		"pid":            100,
		"path":           "/bin/ls",
		"rule_id":        "app_control:1",
		"rule_type":      "BINARY",
		"identifier":     "x",
		"severity":       "high",
		"policy_id":      1,
		"policy_version": 1,
	})
	require.NoError(t, err)
	wantErr := errors.New("graph reader unavailable")
	gr := &stubBlockGraphReader{err: wantErr}
	_, err = rule.Evaluate(t.Context(), []api.Event{{
		EventID: "evt-1", HostID: "host-a", TimestampNs: 1000,
		EventType: "application_control_block", Payload: payload,
	}}, gr)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

// stubBlockGraphReader is the minimal GraphReader the rule needs:
// only GetProcessByPID is exercised. Returning exists=false models
// the "process not yet materialised" race the rule must skip
// silently; returning err models a transient DB error the rule
// must propagate.
type stubBlockGraphReader struct {
	exists bool
	procID int64
	err    error
}

func (s *stubBlockGraphReader) GetProcessByPID(_ context.Context, _ string, _ int, _ int64) (*api.Process, error) {
	if s.err != nil {
		return nil, s.err
	}
	if !s.exists {
		return nil, nil
	}
	return &api.Process{ID: s.procID}, nil
}

func (s *stubBlockGraphReader) GetChildProcesses(_ context.Context, _ string, _ int, _ api.TimeRange) ([]api.Process, error) {
	return nil, nil
}

func (s *stubBlockGraphReader) GetExecChain(_ context.Context, current api.Process) ([]api.Process, error) {
	return []api.Process{current}, nil
}
