package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
)

// stubGraphReader is a no-op GraphReader for rule paths that don't actually query the process graph. The malformed-payload test never
// reaches a graph call because the JSON unmarshal fails before that.
type stubGraphReader struct{}

func (stubGraphReader) GetProcessByPID(context.Context, string, int, int64) (*api.Process, error) {
	return nil, nil
}
func (stubGraphReader) GetChildProcesses(context.Context, string, int, api.TimeRange) ([]api.Process, error) {
	return nil, nil
}
func (stubGraphReader) GetExecChain(context.Context, api.Process) ([]api.Process, error) {
	return nil, nil
}

// errGraphReader returns an error from GetProcessByPID, to prove the rule's best-effort process correlation does NOT
// abort Evaluate (which would drop every finding for the whole batch).
type errGraphReader struct{}

func (errGraphReader) GetProcessByPID(context.Context, string, int, int64) (*api.Process, error) {
	return nil, errors.New("graph unavailable")
}
func (errGraphReader) GetChildProcesses(context.Context, string, int, api.TimeRange) ([]api.Process, error) {
	return nil, nil
}
func (errGraphReader) GetExecChain(context.Context, api.Process) ([]api.Process, error) {
	return nil, nil
}

// TestPrivilegeLaunchdPlistWrite_Fixtures runs every fixture case under fixtures/privilege_launchd_plist_write/ as its own sub-test.
// Add a new case by dropping a *.json file in that directory — no Go edits needed.
func TestPrivilegeLaunchdPlistWrite_Fixtures(t *testing.T) {
	t.Parallel()
	r := &PrivilegeLaunchdPlistWrite{
		AllowedTeamIDs: map[string]struct{}{
			// Synthetic team ID used by the allowlist fixture.
			"FIXTURE-ALLOW": {},
		},
	}
	detectiontestkit.Replay(t, r, "fixtures/privilege_launchd_plist_write")
}

// TestPrivilegeLaunchdPlistWrite_TechniquesMapping pins the MITRE ATT&CK
// mapping the rule reports.
func TestPrivilegeLaunchdPlistWrite_TechniquesMapping(t *testing.T) {
	t.Parallel()
	r := &PrivilegeLaunchdPlistWrite{}
	assert.Equal(t, []string{"T1543.004"}, r.Techniques())
}

// TestPrivilegeLaunchdPlistWrite_AllowedEdgeCases pins the contract of the allowed() helper for the small surface area of code-signing
// values the engine hands it. Exercising these directly (rather than via fixtures) covers the JSON-error and "null literal" branches
// without having to fabricate a process row whose code_signing column carries malformed bytes — MySQL's JSON column type rejects those
// at insert.
func TestPrivilegeLaunchdPlistWrite_AllowedEdgeCases(t *testing.T) {
	t.Parallel()
	r := &PrivilegeLaunchdPlistWrite{
		AllowedTeamIDs: map[string]struct{}{"VENDORALLOW": {}},
	}

	cases := []struct {
		name string
		cs   codeSigningJSON
		want bool
	}{
		{"platform binary", codeSigningJSON{IsPlatformBinary: true}, true},
		{"allowlisted team", codeSigningJSON{TeamID: "VENDORALLOW", IsPlatformBinary: false}, true},
		{"unknown team, no allowlist hit", codeSigningJSON{TeamID: "EVILCORP1", IsPlatformBinary: false}, false},
		{"unsigned (empty team, not platform)", codeSigningJSON{IsPlatformBinary: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, r.allowed(tc.cs))
		})
	}

	// AllowedTeamIDs=nil branch: any non-platform instigator falls through to the "not allowed" return — the rule's
	// default-construction shape.
	rNoList := &PrivilegeLaunchdPlistWrite{}
	assert.False(t, rNoList.allowed(codeSigningJSON{TeamID: "X", IsPlatformBinary: false}))
}

// TestPrivilegeLaunchdPlistWrite_MalformedPayload exercises the json.Unmarshal failure path inside evalEvent: a btm_launch_item_add
// event with a truncated payload is dropped silently. Bypasses the fixture harness because MySQL's JSON column rejects malformed
// payloads at InsertEvents — this branch only fires in-memory if a downstream batcher hands us a partial buffer.
func TestPrivilegeLaunchdPlistWrite_MalformedPayload(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	r := &PrivilegeLaunchdPlistWrite{}

	evt := api.Event{
		EventID:     "ldp-malformed",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "btm_launch_item_add",
		Payload:     json.RawMessage(`{"item_type":"daemon","item_path":`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, stubGraphReader{})
	require.NoError(t, err)
	assert.Empty(t, findings, "malformed payload must be dropped silently")
}

// TestPrivilegeLaunchdPlistWrite_FiresWithoutProcessRow pins the robustness improvement over the old open-based rule: the BTM event
// carries the instigator's code-signing inline, so a daemon registered by a non-platform instigator FIRES even when its process row
// hasn't materialised (stubGraphReader returns nil for GetProcessByPID). The old rule dropped the finding on a missing row; this one
// only loses the optional process-tree link (ProcessID == 0).
func TestPrivilegeLaunchdPlistWrite_FiresWithoutProcessRow(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	r := &PrivilegeLaunchdPlistWrite{}

	evt := api.Event{
		EventID:     "ldp-noproc",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "btm_launch_item_add",
		Payload: json.RawMessage(`{"item_type":"daemon","item_path":"/Library/LaunchDaemons/com.x.plist",` +
			`"managed":false,"instigator_pid":4242,"instigator_code_signing":{"team_id":"","is_platform_binary":false}}`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, stubGraphReader{})
	require.NoError(t, err)
	require.Len(t, findings, 1, "decision uses inline instigator signing; a missing process row must not drop the finding")
	assert.Equal(t, int64(0), findings[0].ProcessID, "best-effort process link is 0 when the row is absent")
}

// TestPrivilegeLaunchdPlistWrite_ProcessLookupErrorStillFires pins that process-tree correlation is TRULY best-effort: a
// GetProcessByPID error must not abort Evaluate (the engine swallows rule errors, so that would silently drop every finding
// for the batch). The finding fires with ProcessID == 0.
func TestPrivilegeLaunchdPlistWrite_ProcessLookupErrorStillFires(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	r := &PrivilegeLaunchdPlistWrite{}

	evt := api.Event{
		EventID:     "ldp-err",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "btm_launch_item_add",
		Payload: json.RawMessage(`{"item_type":"daemon","item_path":"/Library/LaunchDaemons/com.x.plist",` +
			`"managed":false,"instigator_pid":4242,"instigator_code_signing":{"team_id":"","is_platform_binary":false}}`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, errGraphReader{})
	require.NoError(t, err, "a GetProcessByPID error must not abort Evaluate")
	require.Len(t, findings, 1, "best-effort correlation error must not drop the finding")
	assert.Equal(t, int64(0), findings[0].ProcessID)
}

// TestBtmLaunchItemAddPayload_RoundTrip is the wire round-trip PBT (CLAUDE.md: new wire struct → Marshal ∘ Unmarshal == identity)
// for the btm_launch_item_add payload the rule decodes.
func TestBtmLaunchItemAddPayload_RoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		in := btmLaunchItemAddPayload{
			ItemType:       rapid.SampledFrom([]string{"daemon", "agent", "login_item", "app", "user_item"}).Draw(rt, "item_type"),
			ItemPath:       rapid.String().Draw(rt, "item_path"),
			ExecutablePath: rapid.String().Draw(rt, "executable_path"),
			Managed:        rapid.Bool().Draw(rt, "managed"),
			InstigatorPID:  rapid.Int().Draw(rt, "instigator_pid"),
		}
		if rapid.Bool().Draw(rt, "has_cs") {
			in.InstigatorCodeSigning = &codeSigningJSON{
				TeamID:           rapid.String().Draw(rt, "team_id"),
				IsPlatformBinary: rapid.Bool().Draw(rt, "is_platform_binary"),
			}
		}
		b, err := json.Marshal(in)
		require.NoError(rt, err)
		var out btmLaunchItemAddPayload
		require.NoError(rt, json.Unmarshal(b, &out))
		assert.Equal(rt, in, out)
	})
}

// Compile-time check that detection/testkit is referenced (other tests in this package use Replay; the import sits at file scope
// alongside the api import so this declaration keeps the unused-import linter happy without forcing a per-test refactor).
var _ = detectiontestkit.Replay
