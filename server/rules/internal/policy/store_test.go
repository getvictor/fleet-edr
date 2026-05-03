package policy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/rules/internal/policy"
	"github.com/fleetdm/edr/server/testdb"
)

// newTestStore opens an isolated DB and applies rules' schema (which
// includes the policies table + the seed default-policy row). Lives in
// the external test package so the testdb -> rules/bootstrap ->
// rules/internal/policy cycle doesn't bite when this file is in
// `package policy`.
func newTestStore(t *testing.T) *policy.Store {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, bootstrap.ApplySchema(t.Context(), db))
	return policy.NewStore(db)
}

func TestGet_SeedRowPresent(t *testing.T) {
	s := newTestStore(t)
	p, err := s.Get(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)
	assert.Equal(t, api.DefaultPolicyName, p.Name)
	assert.Equal(t, int64(1), p.Version)
	assert.Equal(t, []string{}, p.Blocklist.Paths)
	assert.Equal(t, []string{}, p.Blocklist.Hashes)
	assert.Equal(t, "system", p.UpdatedBy)
}

func TestGet_UnknownName(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get(t.Context(), "other")
	require.ErrorIs(t, err, api.ErrPolicyNotFound)
}

func TestUpdate_BumpsVersionAndNormalizes(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	const (
		hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// Send paths out of order with duplicates + whitespace to exercise normalization.
	// Hashes mix case + duplicates -- post-normalize they must be lowercase, deduped, sorted.
	first, err := s.Update(ctx, api.UpdateRequest{
		Name:   api.DefaultPolicyName,
		Paths:  []string{"/opt/b", " /opt/a ", "/opt/b", "", "/opt/a"},
		Hashes: []string{strings.ToUpper(hashB), hashB, " " + strings.ToUpper(hashA)},
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), first.Version, "seed row is v1; first Update takes it to v2")
	assert.Equal(t, []string{"/opt/a", "/opt/b"}, first.Blocklist.Paths)
	assert.Equal(t, []string{hashA, hashB}, first.Blocklist.Hashes)
	assert.Equal(t, "qa-tester", first.UpdatedBy)
	assert.False(t, first.UpdatedAt.IsZero())

	// A second update bumps the version again and replaces the blocklist entirely.
	second, err := s.Update(ctx, api.UpdateRequest{
		Name:   api.DefaultPolicyName,
		Paths:  []string{"/opt/c"},
		Hashes: nil,
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(3), second.Version)
	assert.Equal(t, []string{"/opt/c"}, second.Blocklist.Paths)
	assert.Equal(t, []string{}, second.Blocklist.Hashes)
}

// TestUpdate_CanonicalizesMacOSSymlinkPaths locks in the rc.7 finding: ESF
// reports the post-resolve path on AUTH_EXEC, so a blocklist entry of
// /tmp/foo silently fails to block when the kernel sees /private/tmp/foo.
// We rewrite at the API boundary so the persisted form matches what the
// kernel actually compares against, regardless of how the operator typed it.
func TestUpdate_CanonicalizesMacOSSymlinkPaths(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	p, err := s.Update(ctx, api.UpdateRequest{
		Name: api.DefaultPolicyName,
		Paths: []string{
			"/tmp/payload", "/tmp", "/var/log/foo", "/var", "/etc/foo", "/etc",
			"/opt/keepasis", "/private/tmp/already",
			// Lookalikes that share a 4-char prefix with /tmp / /var / /etc but
			// are NOT under those directories. The rewrite must be a
			// path-segment match (HasPrefix("/tmp/")), never a substring match.
			"/tmpfoo", "/varlog/x", "/etcetera",
		},
		Actor: "qa",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/etcetera",
		"/opt/keepasis",
		"/private/etc",
		"/private/etc/foo",
		"/private/tmp",
		"/private/tmp/already",
		"/private/tmp/payload",
		"/private/var",
		"/private/var/log/foo",
		"/tmpfoo",
		"/varlog/x",
	}, p.Blocklist.Paths,
		"every /tmp/, /var/, and /etc/ prefix must be rewritten to its /private/... canonical form; lookalike paths (/tmpfoo, /varlog, /etcetera) pass through unchanged")
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
		wantErr    error
		wantErrSub string
	}{
		{
			name:       "relative path rejected",
			paths:      []string{"relative/path"},
			wantErr:    api.ErrInvalidPath,
			wantErrSub: "must be absolute",
		},
		{
			name:       "short hash rejected",
			hashes:     []string{"deadbeef"},
			wantErr:    api.ErrInvalidHash,
			wantErrSub: "64 lowercase hex",
		},
		{
			name:       "non-hex hash rejected",
			hashes:     []string{"z" + strings.Repeat("a", 63)},
			wantErr:    api.ErrInvalidHash,
			wantErrSub: "64 lowercase hex",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Update(ctx, api.UpdateRequest{
				Name:   api.DefaultPolicyName,
				Paths:  tc.paths,
				Hashes: tc.hashes,
				Actor:  "qa-tester",
			})
			require.Error(t, err)
			require.ErrorIs(t, err, tc.wantErr)
			assert.Contains(t, err.Error(), tc.wantErrSub)
		})
	}

	// Seed row untouched -- bad updates must not increment the version.
	p, err := s.Get(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), p.Version)
}

func TestUpdate_RejectsEmptyActor(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Update(t.Context(), api.UpdateRequest{
		Name:  api.DefaultPolicyName,
		Paths: []string{"/opt/x"},
	})
	require.ErrorIs(t, err, api.ErrInvalidUpdateRequest)
	require.ErrorContains(t, err, "actor is required")
}

func TestUpdate_RejectsEmptyName(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Update(t.Context(), api.UpdateRequest{
		Actor: "qa-tester",
	})
	require.ErrorIs(t, err, api.ErrInvalidUpdateRequest)
	require.ErrorContains(t, err, "name is required")
}

func TestUpdate_CreatesMissingRow(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	p, err := s.Update(ctx, api.UpdateRequest{
		Name:  "custom-1",
		Paths: []string{"/opt/x"},
		Actor: "qa-tester",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), p.Version, "fresh row starts at v1")

	// Seed row untouched.
	def, err := s.Get(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	assert.Equal(t, int64(1), def.Version)
}

func TestUpdate_EmptyBlocklistProducesEmptyArrays(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	p, err := s.Update(ctx, api.UpdateRequest{
		Name:   api.DefaultPolicyName,
		Paths:  nil,
		Hashes: nil,
		Actor:  "qa-tester",
	})
	require.NoError(t, err)
	assert.NotNil(t, p.Blocklist.Paths, "paths must be [] not null so clients don't null-check")
	assert.NotNil(t, p.Blocklist.Hashes)
}
