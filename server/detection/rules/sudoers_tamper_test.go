package rules

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/testharness"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

// TestSudoersTamper_Fixtures runs every fixture case under
// fixtures/sudoers_tamper/ as its own sub-test.
func TestSudoersTamper_Fixtures(t *testing.T) {
	r := &SudoersTamper{
		AllowedWriters: map[string]struct{}{
			"/usr/local/bin/fixture-allowed-writer": {},
		},
	}
	testharness.Replay(t, r, "fixtures/sudoers_tamper")
}

// TestSudoersTamper_TechniquesMapping pins the MITRE ATT&CK mapping.
func TestSudoersTamper_TechniquesMapping(t *testing.T) {
	r := &SudoersTamper{}
	assert.Equal(t, []string{"T1548.003"}, r.Techniques())
}

// TestSudoersTamper_AllowedEdgeCases pins the contract of allowed():
// nil allowlist always returns false; populated allowlist hits exact
// path matches. We don't normalise (no trailing-slash stripping, no
// case folding) — matching is byte-equal.
func TestSudoersTamper_AllowedEdgeCases(t *testing.T) {
	rNoList := &SudoersTamper{}
	assert.False(t, rNoList.allowed("/usr/sbin/visudo"),
		"nil allowlist must return false for any path")

	r := &SudoersTamper{AllowedWriters: map[string]struct{}{
		"/usr/sbin/visudo": {},
	}}
	assert.True(t, r.allowed("/usr/sbin/visudo"))
	assert.False(t, r.allowed("/usr/local/bin/visudo"),
		"matching is exact-path; no PATH-walk fallback")
	assert.False(t, r.allowed(""),
		"empty path must not accidentally match an empty-key entry")
}

// TestSudoersTamper_MalformedPayload exercises the unmarshal-failure
// path: the fast-path bytes.Contains lets it through (the magic
// substring is present), then unmarshal trips and the rule drops the
// event silently.
func TestSudoersTamper_MalformedPayload(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := store.Event{
		EventID:     "sud-malformed",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"path":"/etc/sudoers", "flags":`),
	}
	findings, err := r.Evaluate(ctx, []store.Event{evt}, s)
	require.NoError(t, err)
	assert.Empty(t, findings, "malformed payload must be dropped silently")
}

// TestSudoersTamper_OpenRaceWithoutProcess covers the proc==nil race
// guard. Mirrors the same shape as the other open-keyed rules.
func TestSudoersTamper_OpenRaceWithoutProcess(t *testing.T) {
	s := store.OpenTestStore(t)
	ctx := t.Context()
	r := &SudoersTamper{}

	evt := store.Event{
		EventID:     "sud-race",
		HostID:      "fixture-host",
		TimestampNs: 1,
		EventType:   "open",
		Payload:     json.RawMessage(`{"pid":99999,"path":"/etc/sudoers","flags":1}`),
	}
	require.NoError(t, s.InsertEvents(ctx, []store.Event{evt}))
	require.NoError(t, graph.NewBuilder(s, slog.Default()).ProcessBatch(ctx, []store.Event{evt}))

	findings, err := r.Evaluate(ctx, []store.Event{evt}, s)
	require.NoError(t, err)
	assert.Empty(t, findings, "race against process materialisation must skip silently")
}
