package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeHostEnvelopes exercises the JSONL decode branches without a checked-in malformed fixture: the happy path, blank-line
// skipping, a malformed line, a file that mixes host_ids, and an effectively-empty input.
func TestDecodeHostEnvelopes(t *testing.T) {
	t.Parallel()
	const valid = `{"event_id":"e1","host_id":"H1","timestamp_ns":1,"event_type":"exec","payload":{}}
{"event_id":"e2","host_id":"H1","timestamp_ns":2,"event_type":"fork","payload":{}}`

	t.Run("valid multi-line shares one host_id", func(t *testing.T) {
		t.Parallel()
		envs, hostID, err := decodeHostEnvelopes([]byte(valid), "ok.jsonl")
		require.NoError(t, err)
		assert.Equal(t, "H1", hostID)
		assert.Len(t, envs, 2)
	})

	t.Run("blank lines are skipped", func(t *testing.T) {
		t.Parallel()
		envs, _, err := decodeHostEnvelopes([]byte("\n  \n"+valid+"\n"), "blanks.jsonl")
		require.NoError(t, err)
		assert.Len(t, envs, 2)
	})

	t.Run("malformed line is an error", func(t *testing.T) {
		t.Parallel()
		_, _, err := decodeHostEnvelopes([]byte(`{not json}`), "bad.jsonl")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse host corpus")
	})

	t.Run("mixed host_ids is an error", func(t *testing.T) {
		t.Parallel()
		mixed := `{"event_id":"e1","host_id":"H1","timestamp_ns":1,"event_type":"exec","payload":{}}
{"event_id":"e2","host_id":"H2","timestamp_ns":2,"event_type":"exec","payload":{}}`
		_, _, err := decodeHostEnvelopes([]byte(mixed), "mixed.jsonl")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mixes host_ids")
	})

	t.Run("effectively-empty input is an error", func(t *testing.T) {
		t.Parallel()
		_, _, err := decodeHostEnvelopes([]byte("\n   \n"), "empty.jsonl")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is empty")
	})
}

// TestLoadHostEnvelopes_ReadError covers the embed-read failure branch (a name that is not an embedded corpus file).
func TestLoadHostEnvelopes_ReadError(t *testing.T) {
	t.Parallel()
	_, _, err := loadHostEnvelopes("does-not-exist.jsonl")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read host corpus")
}

// TestDecodeAttackScenario exercises the YAML decode + validate branches: a valid scenario, strict rejection of an unknown key,
// malformed YAML, and a well-formed scenario that fails Validate().
func TestDecodeAttackScenario(t *testing.T) {
	t.Parallel()
	const valid = `name: t
mitre: T1059
host:
  id: H1
timeline:
  - at: 0ms
    type: exec
    pid: 2
    path: /bin/x`

	t.Run("valid scenario decodes", func(t *testing.T) {
		t.Parallel()
		sc, err := decodeAttackScenario([]byte(valid), "ok.yaml")
		require.NoError(t, err)
		assert.Equal(t, "t", sc.Name)
		assert.Len(t, sc.Timeline, 1)
	})

	t.Run("unknown key is rejected by strict decode", func(t *testing.T) {
		t.Parallel()
		_, err := decodeAttackScenario([]byte(valid+"\nbogus_key: 1\n"), "unknown.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse corpus")
	})

	t.Run("malformed yaml is an error", func(t *testing.T) {
		t.Parallel()
		_, err := decodeAttackScenario([]byte("name: [unterminated"), "bad.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse corpus")
	})

	t.Run("validation failure surfaces", func(t *testing.T) {
		t.Parallel()
		// Well-formed YAML, but no timeline, so Validate() rejects it.
		_, err := decodeAttackScenario([]byte("name: t\nhost:\n  id: H1\n"), "novalidate.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validate corpus")
	})
}

// TestLoadAttackScenario_ReadError covers the embed-read failure branch.
func TestLoadAttackScenario_ReadError(t *testing.T) {
	t.Parallel()
	_, err := loadAttackScenario("does-not-exist.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read embedded corpus")
}
