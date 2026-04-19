package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := store.OpenTestStore(t)
	return New(s.DB())
}

func TestGet_SeedRowPresent(t *testing.T) {
	s := newTestStore(t)
	p, err := s.Get(t.Context(), DefaultName)
	require.NoError(t, err)
	assert.Equal(t, DefaultName, p.Name)
	assert.Equal(t, int64(1), p.Version)
	assert.Equal(t, []string{}, p.Blocklist.Paths)
	assert.Equal(t, []string{}, p.Blocklist.Hashes)
	assert.Equal(t, "system", p.UpdatedBy)
}

func TestGet_UnknownName(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(t.Context(), "other")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestUpdate_BumpsVersionAndNormalizes(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Send paths out of order with duplicates + whitespace to exercise normalization.
	p, err := s.Update(ctx, UpdateRequest{
		Name:   DefaultName,
		Paths:  []string{"/opt/b", " /opt/a ", "/opt/b", "", "/opt/a"},
		Hashes: []string{"DEADBEEF", "deadbeef", " CAFEBABE"},
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), p.Version, "seed row is v1; first Update takes it to v2")
	assert.Equal(t, []string{"/opt/a", "/opt/b"}, p.Blocklist.Paths)
	assert.Equal(t, []string{"cafebabe", "deadbeef"}, p.Blocklist.Hashes)
	assert.Equal(t, "qa-tester", p.UpdatedBy)
	assert.False(t, p.UpdatedAt.IsZero())

	// A second update bumps the version again and replaces the blocklist entirely.
	p2, err := s.Update(ctx, UpdateRequest{
		Name:   DefaultName,
		Paths:  []string{"/opt/c"},
		Hashes: nil,
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(3), p2.Version)
	assert.Equal(t, []string{"/opt/c"}, p2.Blocklist.Paths)
	assert.Equal(t, []string{}, p2.Blocklist.Hashes)
}

func TestUpdate_RejectsEmptyActor(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Update(t.Context(), UpdateRequest{
		Name:  DefaultName,
		Paths: []string{"/opt/x"},
	})
	require.ErrorContains(t, err, "actor is required")
}

func TestUpdate_RejectsEmptyName(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Update(t.Context(), UpdateRequest{
		Actor: "qa-tester",
	})
	require.ErrorContains(t, err, "name is required")
}

func TestUpdate_CreatesMissingRow(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	p, err := s.Update(ctx, UpdateRequest{
		Name:  "custom-1",
		Paths: []string{"/opt/x"},
		Actor: "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), p.Version, "fresh row starts at v1")

	// Seed row untouched.
	def, err := s.Get(ctx, DefaultName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), def.Version)
}

func TestUpdate_EmptyBlocklistProducesEmptyArrays(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	p, err := s.Update(ctx, UpdateRequest{
		Name:   DefaultName,
		Paths:  nil,
		Hashes: nil,
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.NotNil(t, p.Blocklist.Paths, "paths must be [] not null so clients don't null-check")
	assert.NotNil(t, p.Blocklist.Hashes)
}
