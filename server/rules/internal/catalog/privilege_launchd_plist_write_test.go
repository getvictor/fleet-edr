package catalog

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
)

// TestLaunchDaemonSubject pins the dedup-subject bound: a short item path stays human-readable, while a path that would
// overflow alerts.subject VARCHAR(255) falls back to a stable hashed subject so the alert INSERT cannot fail or collide.
func TestLaunchDaemonSubject(t *testing.T) {
	t.Parallel()
	short := "/Library/LaunchDaemons/com.x.plist"
	assert.Equal(t, "launchdaemon:"+short, launchDaemonSubject(short), "short path stays human-readable")

	long := "/Library/LaunchDaemons/" + strings.Repeat("a", 300) + ".plist"
	got := launchDaemonSubject(long)
	assert.LessOrEqual(t, len(got), subjectColumnLimit, "long path must fit alerts.subject VARCHAR(255)")
	assert.True(t, strings.HasPrefix(got, "launchdaemon:sha256:"), "long path falls back to a hashed subject")
	assert.Equal(t, got, launchDaemonSubject(long), "hashing is stable for the same path")
}

// stubGraphReader is a no-op GraphReader. The rule is process-optional (ADR-0008 amendment): its decision rides the
// event payload alone, so it never queries the graph. Evaluate still takes a GraphReader, hence the stub.
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
func (stubGraphReader) GetNetworkEventsForProcess(context.Context, string, int, api.TimeRange) ([]api.Event, error) {
	return nil, nil
}

// TestPrivilegeLaunchdPlistWrite_Fixtures runs every fixture case under fixtures/privilege_launchd_plist_write/ as its own sub-test.
// Add a new case by dropping a *.json file in that directory; no Go edits needed.
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

// TestPrivilegeLaunchdPlistWrite_AllowedEdgeCases pins the contract of the allowed() helper over the executable's code-signing: an
// Apple platform binary or an allowlisted team ID is trusted; an ad-hoc/unsigned or unknown-vendor executable is not. Notarization
// is deliberately not a trust signal (see the rule doc). Exercised directly so the platform-binary + allowlist branches are covered
// without fabricating a fixture per branch.
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
		{"ad-hoc / unsigned (empty team, not platform)", codeSigningJSON{IsPlatformBinary: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, r.allowed(tc.cs))
		})
	}

	// AllowedTeamIDs=nil branch: any non-platform executable falls through to "not allowed", the rule's
	// default-construction shape.
	rNoList := &PrivilegeLaunchdPlistWrite{}
	assert.False(t, rNoList.allowed(codeSigningJSON{TeamID: "X", IsPlatformBinary: false}))
}

// TestPrivilegeLaunchdPlistWrite_MalformedPayload exercises the json.Unmarshal failure path inside evalEvent: a btm_launch_item_add
// event with a truncated payload is dropped silently rather than erroring the batch.
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

// TestPrivilegeLaunchdPlistWrite_FiresOnUnsignedExecutable pins the corrected decision (ADR-0008 amendment): the rule keys on the
// REGISTERED EXECUTABLE's code-signing, not the instigator. Here the instigator is Apple's smd (a platform binary), which the old
// instigator-gated rule would have skipped, but the executable is unsigned, so the rule fires. The alert is process-optional
// (ProcessID 0) and dedups on the item path.
func TestPrivilegeLaunchdPlistWrite_FiresOnUnsignedExecutable(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	r := &PrivilegeLaunchdPlistWrite{}

	evt := api.Event{
		EventID:     "ldp-fire",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "btm_launch_item_add",
		Payload: json.RawMessage(`{"item_type":"daemon","item_path":"/Library/LaunchDaemons/com.x.plist",` +
			`"executable_path":"/tmp/x","managed":false,` +
			`"executable_code_signing":{"team_id":"","is_platform_binary":false},` +
			`"instigator_pid":93,"instigator_code_signing":{"signing_id":"com.apple.xpc.smd","is_platform_binary":true}}`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, stubGraphReader{})
	require.NoError(t, err)
	require.Len(t, findings, 1, "an unsigned executable registered as a system daemon must fire regardless of the smd instigator")
	assert.Equal(t, int64(0), findings[0].ProcessID, "process-optional: a BTM persistence alert carries no process link")
	assert.Equal(t, "launchdaemon:/Library/LaunchDaemons/com.x.plist", findings[0].Subject, "dedup subject is the item path")
	assert.Contains(t, findings[0].Description, "/tmp/x", "description names the registered executable")
}

// TestPrivilegeLaunchdPlistWrite_SkipsWhenExecutableSigningAbsent pins the high-precision skip when the extension could not read the
// registered executable's signing (object absent): with no decision input the rule must not fire.
func TestPrivilegeLaunchdPlistWrite_SkipsWhenExecutableSigningAbsent(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	r := &PrivilegeLaunchdPlistWrite{}

	evt := api.Event{
		EventID:     "ldp-nosig",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "btm_launch_item_add",
		Payload: json.RawMessage(`{"item_type":"daemon","item_path":"/Library/LaunchDaemons/com.x.plist",` +
			`"executable_path":"/tmp/x","managed":false,"instigator_pid":93}`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, stubGraphReader{})
	require.NoError(t, err)
	assert.Empty(t, findings, "no executable code-signing => cannot classify => skip")
}

// TestBtmLaunchItemAddPayload_RoundTrip is the wire round-trip PBT (CLAUDE.md: new wire struct → Marshal ∘ Unmarshal == identity)
// for the btm_launch_item_add payload the rule decodes, including the executable_code_signing decision input.
func TestBtmLaunchItemAddPayload_RoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		in := btmLaunchItemAddPayload{
			ItemType:       rapid.SampledFrom([]string{"daemon", "agent", "login_item", "app", "user_item"}).Draw(rt, "item_type"),
			ItemPath:       rapid.String().Draw(rt, "item_path"),
			ExecutablePath: rapid.String().Draw(rt, "executable_path"),
			Managed:        rapid.Bool().Draw(rt, "managed"),
			InstigatorPID:  rapid.Int().Draw(rt, "instigator_pid"),
		}
		if rapid.Bool().Draw(rt, "has_exec_cs") {
			in.ExecutableCodeSigning = &codeSigningJSON{
				TeamID:           rapid.String().Draw(rt, "exec_team_id"),
				IsPlatformBinary: rapid.Bool().Draw(rt, "exec_is_platform"),
			}
		}
		if rapid.Bool().Draw(rt, "has_instigator_cs") {
			in.InstigatorCodeSigning = &codeSigningJSON{
				TeamID:           rapid.String().Draw(rt, "inst_team_id"),
				IsPlatformBinary: rapid.Bool().Draw(rt, "inst_is_platform"),
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
