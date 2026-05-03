package catalog

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
)

// stubGraphReader is a no-op GraphReader for rule paths that don't
// actually query the process graph. The malformed-payload test never
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

// TestPrivilegeLaunchdPlistWrite_Fixtures runs every fixture case under
// fixtures/privilege_launchd_plist_write/ as its own sub-test. Add a new
// case by dropping a *.json file in that directory — no Go edits needed.
func TestPrivilegeLaunchdPlistWrite_Fixtures(t *testing.T) {
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
	r := &PrivilegeLaunchdPlistWrite{}
	assert.Equal(t, []string{"T1543.004"}, r.Techniques())
}

// TestPrivilegeLaunchdPlistWrite_AllowedEdgeCases pins the contract of
// the allowed() helper for the small surface area of code-signing values
// the engine hands it. Exercising these directly (rather than via
// fixtures) covers the JSON-error and "null literal" branches without
// having to fabricate a process row whose code_signing column carries
// malformed bytes — MySQL's JSON column type rejects those at insert.
func TestPrivilegeLaunchdPlistWrite_AllowedEdgeCases(t *testing.T) {
	r := &PrivilegeLaunchdPlistWrite{
		AllowedTeamIDs: map[string]struct{}{"VENDORALLOW": {}},
	}

	cases := []struct {
		name string
		raw  api.NullRawJSON
		want bool
	}{
		{"empty slice (DB NULL)", nil, false},
		{"json null literal", api.NullRawJSON("null"), false},
		{"malformed JSON", api.NullRawJSON("{not json"), false},
		{
			"platform binary",
			api.NullRawJSON(`{"team_id":"","signing_id":"com.apple.installd","flags":0,"is_platform_binary":true}`),
			true,
		},
		{
			"allowlisted team",
			api.NullRawJSON(`{"team_id":"VENDORALLOW","signing_id":"x","flags":0,"is_platform_binary":false}`),
			true,
		},
		{
			"unknown team, no allowlist hit",
			api.NullRawJSON(`{"team_id":"EVILCORP1","signing_id":"x","flags":0,"is_platform_binary":false}`),
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, r.allowed(tc.raw))
		})
	}

	// AllowedTeamIDs=nil branch: any non-platform writer falls through to
	// the "not allowed" return. Separated from the table above because
	// it's the rule's default-construction shape.
	rNoList := &PrivilegeLaunchdPlistWrite{}
	assert.False(t, rNoList.allowed(
		api.NullRawJSON(`{"team_id":"X","is_platform_binary":false}`),
	))
}

// TestPrivilegeLaunchdPlistWrite_MalformedPayload exercises the
// json.Unmarshal failure path inside evalEvent. The fast-path
// bytes.Contains gate lets the malformed payload through (the magic
// substring is present), then unmarshal fails and the rule drops the
// event silently. We bypass the fixture harness because MySQL's JSON
// column rejects malformed payloads at InsertEvents — this branch only
// fires in-memory if a downstream batcher hands us a partial buffer.
func TestPrivilegeLaunchdPlistWrite_MalformedPayload(t *testing.T) {
	ctx := t.Context()
	r := &PrivilegeLaunchdPlistWrite{}

	evt := api.Event{
		EventID:     "ldp-malformed",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"path":"/Library/LaunchDaemons/x.plist", "flags":`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, stubGraphReader{})
	require.NoError(t, err)
	assert.Empty(t, findings, "malformed payload must be dropped silently")
}

// TestPrivilegeLaunchdPlistWrite_OpenRaceWithoutProcess covers the
// proc==nil race guard. The fixture negative_open_without_process.json
// exercises the same branch via Replay (above); this Go-level test
// uses the stub GraphReader (returning nil for GetProcessByPID) so
// the rule sees a missing process row without needing the live
// detection persistence layer.
func TestPrivilegeLaunchdPlistWrite_OpenRaceWithoutProcess(t *testing.T) {
	ctx := t.Context()
	r := &PrivilegeLaunchdPlistWrite{}

	evt := api.Event{
		EventID:     "ldp-race",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"pid":99999,"path":"/Library/LaunchDaemons/com.race.plist","flags":1}`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, stubGraphReader{})
	require.NoError(t, err)
	assert.Empty(t, findings, "race against process materialisation must skip silently")
}

// Compile-time check that detection/testkit is referenced (other tests in
// this package use Replay; the import sits at file scope alongside
// the api import so this declaration keeps the unused-import linter
// happy without forcing a per-test refactor).
var _ = detectiontestkit.Replay
