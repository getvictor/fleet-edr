package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/rules/api"
)

// TestSudoersTamper_Fixtures runs every fixture case under
// fixtures/sudoers_tamper/ as its own sub-test.
func TestSudoersTamper_Fixtures(t *testing.T) {
	t.Parallel()
	r := &SudoersTamper{Exclusions: &fakeExclusions{entries: []fakeExcl{
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/usr/local/bin/fixture-allowed-writer"},
	}}}
	detectiontestkit.Replay(t, r, "fixtures/sudoers_tamper")
}

// TestSudoersTamper_TechniquesMapping pins the MITRE ATT&CK mapping.
func TestSudoersTamper_TechniquesMapping(t *testing.T) {
	t.Parallel()
	r := &SudoersTamper{}
	assert.Equal(t, []string{"T1548.003"}, r.Techniques())
}

// TestSudoersTamper_ExcludedEdgeCases pins the contract of excluded(): a nil resolver always returns false; a resolver entry hits
// per its match-type semantics (here path_glob, which is exact when the entry has no `*`).
func TestSudoersTamper_ExcludedEdgeCases(t *testing.T) {
	t.Parallel()
	rNoList := &SudoersTamper{}
	assert.False(t, rNoList.excluded("/usr/sbin/visudo", "host-a"),
		"nil resolver must return false for any path")

	r := &SudoersTamper{Exclusions: &fakeExclusions{entries: []fakeExcl{
		{ruleID: "sudoers_tamper", matchType: api.ExclusionMatchPathGlob, value: "/usr/sbin/visudo"},
	}}}
	assert.True(t, r.excluded("/usr/sbin/visudo", "host-a"))
	assert.False(t, r.excluded("/usr/local/bin/visudo", "host-a"),
		"a literal entry is exact-path; no PATH-walk fallback")
	assert.False(t, r.excluded("", "host-a"),
		"empty path must not match a non-empty entry")
}

// TestSudoersTamper_MalformedPayload exercises the unmarshal-failure path: the fast-path bytes.Contains lets it through (the magic
// substring is present), then unmarshal trips and the rule drops the event silently.
func TestSudoersTamper_MalformedPayload(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := api.Event{
		EventID:     "sud-malformed",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"path":"/etc/sudoers", "flags":`),
	}
	findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "malformed payload must be dropped silently")
}

// TestSudoersTamper_OpenRaceWithoutProcess covers the proc==nil race
// guard. Mirrors the same shape as the other open-keyed rules.
func TestSudoersTamper_OpenRaceWithoutProcess(t *testing.T) {
	t.Parallel()
	s := openCatalogStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := api.Event{
		EventID:     "sud-race",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"pid":99999,"path":"/etc/sudoers","flags":1}`),
	}
	require.NoError(t, s.InsertEvents(ctx, []api.Event{evt}))
	require.NoError(t, s.ProcessBatch(ctx, []api.Event{evt}))

	findings, err := r.Evaluate(ctx, []api.Event{evt}, s.GraphReader())
	require.NoError(t, err)
	assert.Empty(t, findings, "race against process materialisation must skip silently")
}
