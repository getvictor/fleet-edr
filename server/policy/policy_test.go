package policy

import (
	"strings"
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

	const (
		hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// Send paths out of order with duplicates + whitespace to exercise normalization.
	// Hashes mix case + duplicates — post-normalize they must be lowercase, deduped, sorted.
	p, err := s.Update(ctx, UpdateRequest{
		Name:   DefaultName,
		Paths:  []string{"/opt/b", " /opt/a ", "/opt/b", "", "/opt/a"},
		Hashes: []string{strings.ToUpper(hashB), hashB, " " + strings.ToUpper(hashA)},
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), p.Version, "seed row is v1; first Update takes it to v2")
	assert.Equal(t, []string{"/opt/a", "/opt/b"}, p.Blocklist.Paths)
	assert.Equal(t, []string{hashA, hashB}, p.Blocklist.Hashes)
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

// TestUpdate_CanonicalizesMacOSSymlinkPaths locks in the rc.7 finding: ESF
// reports the post-resolve path on AUTH_EXEC, so a blocklist entry of
// /tmp/foo silently fails to block when the kernel sees /private/tmp/foo.
// We rewrite at the API boundary so the persisted form matches what the
// kernel actually compares against, regardless of how the operator typed it.
func TestUpdate_CanonicalizesMacOSSymlinkPaths(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	p, err := s.Update(ctx, UpdateRequest{
		Name:  DefaultName,
		Paths: []string{"/tmp/payload", "/tmp", "/var/log/foo", "/var", "/opt/keepasis", "/private/tmp/already"},
		Actor: "qa",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/opt/keepasis",
		"/private/tmp",
		"/private/tmp/already",
		"/private/tmp/payload",
		"/private/var",
		"/private/var/log/foo",
	}, p.Blocklist.Paths,
		"every /tmp/* and /var/* prefix must be rewritten to its /private/... canonical form; other paths pass through")
}

// TestUpdate_RejectsInvalidBlocklistEntries locks in the Phase 2 validation contract: a
// malformed path (relative, empty after trim) or hash (not 64 lowercase hex chars) fails
// the update before anything is persisted. Without this, bad operator input would be
// versioned + audited + fanned out to agents that silently can't apply it.
func TestUpdate_RejectsInvalidBlocklistEntries(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	cases := []struct {
		name       string
		paths      []string
		hashes     []string
		wantErrSub string
	}{
		{
			name:       "relative path rejected",
			paths:      []string{"relative/path"},
			wantErrSub: "must be absolute",
		},
		{
			name:       "short hash rejected",
			hashes:     []string{"deadbeef"},
			wantErrSub: "64 lowercase hex",
		},
		{
			name:       "non-hex hash rejected",
			hashes:     []string{"z" + strings.Repeat("a", 63)},
			wantErrSub: "64 lowercase hex",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Update(ctx, UpdateRequest{
				Name:   DefaultName,
				Paths:  tc.paths,
				Hashes: tc.hashes,
				Actor:  "qa-tester",
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSub)
		})
	}

	// Seed row untouched — bad updates must not increment the version.
	p, err := s.Get(ctx, DefaultName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), p.Version)
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
