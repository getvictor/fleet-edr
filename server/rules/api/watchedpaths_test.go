package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestValidateWatchedPaths_AcceptsTheShapesTheIssueNames(t *testing.T) {
	t.Parallel()
	require.NoError(t, ValidateWatchedPaths(nil), "the empty set is what every host already watches")
	require.NoError(t, ValidateWatchedPaths([]WatchedPath{
		{Path: "/Library/StartupItems/", Match: WatchedPathPrefix},
		{Path: "/etc/emond.d/rules/", Match: WatchedPathPrefix},
		{Path: "/private/var/root/.ssh/", Match: WatchedPathPrefix},
		{Path: "/Users/Shared/canary.docx", Match: WatchedPathLiteral},
		{Path: "/etc/sudoers", Match: WatchedPathLiteral},
		// The same path as a literal and a prefix are two different entries.
		{Path: "/Library/Keychains/", Match: WatchedPathPrefix},
		{Path: "/Library/Keychains/System.keychain", Match: WatchedPathLiteral},
	}))
}

// spec:server-admin-surface/watched-file-paths-are-configured-over-the-api/a-set-the-server-would-not-watch-is-refused
func TestValidateWatchedPaths_RefusesWhatItShouldNotWatch(t *testing.T) {
	t.Parallel()
	prefix := func(p string) WatchedPath { return WatchedPath{Path: p, Match: WatchedPathPrefix} }
	literal := func(p string) WatchedPath { return WatchedPath{Path: p, Match: WatchedPathLiteral} }
	cases := []struct {
		name   string
		paths  []WatchedPath
		reason string
	}{
		{"relative path", []WatchedPath{literal("etc/hosts")}, "absolute"},
		{"empty path", []WatchedPath{literal("")}, "absolute"},
		{"empty segment", []WatchedPath{literal("/etc//hosts")}, "segment"},
		{"dot segment", []WatchedPath{literal("/etc/./hosts")}, "segment"},
		{"dot-dot segment", []WatchedPath{prefix("/Library/../Users/")}, "segment"},
		{"control character", []WatchedPath{literal("/etc/ho\nsts")}, "control character"},
		{"delete character", []WatchedPath{literal("/etc/hosts\x7f")}, "control character"},
		{"too long", []WatchedPath{literal("/" + strings.Repeat("a", MaxWatchedPathBytes))}, "longer than"},
		{"literal ending in a slash", []WatchedPath{literal("/Library/StartupItems/")}, `must not end in "/"`},
		{"prefix without a trailing slash", []WatchedPath{prefix("/Library/StartupItems")}, `must end in "/"`},
		{"root prefix", []WatchedPath{prefix("/")}, "segment"},
		{"top-level prefix", []WatchedPath{prefix("/Users/")}, "below a top-level directory"},
		{"top-level prefix through the firmlink", []WatchedPath{prefix("/private/etc/")}, "below a top-level directory"},
		{"firmlink parent itself", []WatchedPath{prefix("/private/")}, "below a top-level directory"},
		{"unknown match", []WatchedPath{{Path: "/Library/StartupItems/", Match: "recursive_glob"}}, "unknown match"},
		{"duplicate", []WatchedPath{prefix("/Library/StartupItems/"), prefix("/Library/StartupItems/")}, "more than once"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateWatchedPaths(tc.paths)
			require.ErrorIs(t, err, ErrInvalidWatchedPaths)
			assert.Contains(t, err.Error(), tc.reason)
		})
	}
}

func TestValidateWatchedPaths_BoundsTheSetSize(t *testing.T) {
	t.Parallel()
	full := make([]WatchedPath, MaxWatchedPaths)
	for i := range full {
		full[i] = WatchedPath{Path: "/Library/Watched/" + strings.Repeat("x", i+1), Match: WatchedPathLiteral}
	}
	require.NoError(t, ValidateWatchedPaths(full))

	over := append(slices.Clone(full), WatchedPath{Path: "/Library/Watched/one-too-many", Match: WatchedPathLiteral})
	err := ValidateWatchedPaths(over)
	require.ErrorIs(t, err, ErrInvalidWatchedPaths)
	assert.Contains(t, err.Error(), "at most 32")
}

func TestValidateWatchedPaths_NamesTheEntryItRefuses(t *testing.T) {
	t.Parallel()
	err := ValidateWatchedPaths([]WatchedPath{
		{Path: "/Library/StartupItems/", Match: WatchedPathPrefix},
		{Path: "/Users/", Match: WatchedPathPrefix},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `entry 1 ("/Users/")`)
}

func TestValidateWatchedPaths_AcceptsAPathAtTheLengthBound(t *testing.T) {
	t.Parallel()
	atBound := "/Library/" + strings.Repeat("a", MaxWatchedPathBytes-len("/Library/"))
	require.Len(t, atBound, MaxWatchedPathBytes)
	require.NoError(t, ValidateWatchedPaths([]WatchedPath{{Path: atBound, Match: WatchedPathLiteral}}))
}

// TestSetWatchedPathsPayload_JSONRoundTrip is the Marshal-then-Unmarshal identity check the repo asks of a new wire shape. The json tags
// are what the agent envelope and the extension decoder read, so a renamed tag here breaks every host.
func TestSetWatchedPathsPayload_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := SetWatchedPathsPayload{
			Version: rapid.Int64().Draw(t, "version"),
			Epoch:   rapid.Int64().Draw(t, "epoch"),
			Paths: rapid.SliceOfN(rapid.Custom(func(t *rapid.T) WatchedPath {
				return WatchedPath{
					Path:  rapid.String().Draw(t, "path"),
					Match: rapid.SampledFrom([]WatchedPathMatch{WatchedPathLiteral, WatchedPathPrefix}).Draw(t, "match"),
				}
			}), 0, 8).Draw(t, "paths"),
		}
		b, err := json.Marshal(want)
		require.NoError(t, err)
		var got SetWatchedPathsPayload
		require.NoError(t, json.Unmarshal(b, &got))
		assert.Equal(t, want, got)
	})
}

// TestSetWatchedPathsPayload_WireShape pins the literal keys the extension decodes (WatchedPaths.swift).
func TestSetWatchedPathsPayload_WireShape(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(SetWatchedPathsPayload{Version: 3, Epoch: 7, Paths: []WatchedPath{{Path: "/etc/emond.d/", Match: WatchedPathPrefix}}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":3,"epoch":7,"paths":[{"path":"/etc/emond.d/","match":"prefix"}]}`, string(b))
}
