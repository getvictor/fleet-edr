package api

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

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
		{"NUL, which would truncate the path the kernel receives", []WatchedPath{prefix("/Users/\x00ignored/")}, "control character"},
		{"delete character", []WatchedPath{literal("/etc/hosts\x7f")}, "control character"},
		{"too long", []WatchedPath{literal("/" + strings.Repeat("a", MaxWatchedPathBytes))}, "longer than"},
		{
			"fits as written but not in its /private spelling",
			[]WatchedPath{literal("/etc/" + strings.Repeat("a", MaxWatchedPathBytes-len("/etc/")))},
			"longer than",
		},
		{"literal ending in a slash", []WatchedPath{literal("/Library/StartupItems/")}, `must not end in "/"`},
		{"prefix without a trailing slash", []WatchedPath{prefix("/Library/StartupItems")}, `must end in "/"`},
		{"root prefix", []WatchedPath{prefix("/")}, "segment"},
		{"top-level prefix", []WatchedPath{prefix("/Users/")}, "below a top-level directory"},
		{"top-level prefix through the firmlink", []WatchedPath{prefix("/private/etc/")}, "below a top-level directory"},
		{"firmlink parent itself", []WatchedPath{prefix("/private/")}, "below a top-level directory"},
		{"unknown match", []WatchedPath{{Path: "/Library/StartupItems/", Match: "recursive_glob"}}, "unknown match"},
		{"duplicate", []WatchedPath{prefix("/Library/StartupItems/"), prefix("/Library/StartupItems/")}, "more than once"},
		{"duplicate through the firmlink", []WatchedPath{prefix("/etc/emond.d/"), prefix("/private/etc/emond.d/")}, "more than once"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateWatchedPaths(tc.paths)
			require.ErrorIs(t, err, ErrInvalidWatchedPaths)
			require.ErrorContains(t, err, tc.reason)
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
	require.ErrorContains(t, err, "at most 32")
}

func TestValidateWatchedPaths_NamesTheEntryItRefuses(t *testing.T) {
	t.Parallel()
	err := ValidateWatchedPaths([]WatchedPath{
		{Path: "/Library/StartupItems/", Match: WatchedPathPrefix},
		{Path: "/Users/", Match: WatchedPathPrefix},
	})
	require.ErrorContains(t, err, `entry 1 ("/Users/")`)
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
	payload := SetWatchedPathsPayload{Version: 3, Epoch: 7, Paths: []WatchedPath{{Path: "/etc/emond.d/", Match: WatchedPathPrefix}}}
	b, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":3,"epoch":7,"paths":[{"path":"/etc/emond.d/","match":"prefix"}]}`, string(b))
}

// PATH_MAX is 1024 and counts the NUL that terminates the C string es_mute_path takes, so a 1023-byte path is the longest that fits.
// Pinned with literals rather than the constant, which is the thing being checked.
func TestValidateWatchedPaths_LeavesRoomForTheNUL(t *testing.T) {
	t.Parallel()
	path := func(n int) []WatchedPath {
		return []WatchedPath{{Path: "/Library/" + strings.Repeat("a", n-len("/Library/")), Match: WatchedPathLiteral}}
	}
	require.NoError(t, ValidateWatchedPaths(path(1023)))
	require.ErrorIs(t, ValidateWatchedPaths(path(1024)), ErrInvalidWatchedPaths)
}

// The set's encoded size is bounded because the fan-out repeats the payload on every row of a batched insert. It is measured as the
// server encodes it, so a path of escapable bytes counts at its escaped size.
func TestValidateWatchedPaths_BoundsTheEncodedSetSize(t *testing.T) {
	t.Parallel()
	// Eight paths of ~1000 bytes encode to just under 8 KiB; one more path of the same size passes it.
	entry := func(i int) WatchedPath {
		return WatchedPath{Path: fmt.Sprintf("/Library/Watched/%02d-", i) + strings.Repeat("a", 970), Match: WatchedPathLiteral}
	}
	fits := []WatchedPath{entry(0), entry(1), entry(2), entry(3), entry(4), entry(5), entry(6), entry(7)}
	encoded, err := json.Marshal(fits)
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), MaxWatchedPathSetBytes)
	require.NoError(t, ValidateWatchedPaths(fits))

	require.ErrorContains(t, ValidateWatchedPaths(append(slices.Clone(fits), entry(8))), "at most 8192")

	// Two paths of '<' bytes, each within the per-path limit and about 2 KiB raw together, but each '<' encodes as \u003c, six bytes.
	escaped := []WatchedPath{
		{Path: "/Library/a/" + strings.Repeat("<", 1000), Match: WatchedPathLiteral},
		{Path: "/Library/b/" + strings.Repeat("<", 1000), Match: WatchedPathLiteral},
	}
	require.ErrorContains(t, ValidateWatchedPaths(escaped), "at most 8192")
}

// TestWatchedPathSet_JSONRoundTrip pins the REST shape of the stored set: every field survives Marshal then Unmarshal, including an
// absent update time and actor, which the seeded set reports.
func TestWatchedPathSet_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		want := WatchedPathSet{
			Version: rapid.Int64().Draw(t, "version"),
			Paths: rapid.SliceOfN(rapid.Custom(func(t *rapid.T) WatchedPath {
				return WatchedPath{
					Path:  rapid.String().Draw(t, "path"),
					Match: rapid.SampledFrom([]WatchedPathMatch{WatchedPathLiteral, WatchedPathPrefix}).Draw(t, "match"),
				}
			}), 0, 8).Draw(t, "paths"),
			UpdatedBy: rapid.String().Draw(t, "updated_by"),
		}
		if rapid.Bool().Draw(t, "updated") {
			at := time.UnixMicro(rapid.Int64Range(0, 1<<50).Draw(t, "updated_at")).UTC()
			want.UpdatedAt = &at
		}
		b, err := json.Marshal(want)
		require.NoError(t, err)
		var got WatchedPathSet
		require.NoError(t, json.Unmarshal(b, &got))
		if want.Paths == nil {
			want.Paths = []WatchedPath{}
		}
		if got.Paths == nil {
			got.Paths = []WatchedPath{}
		}
		assert.Equal(t, want, got)
	})
}

// FuzzValidateWatchedPaths feeds arbitrary entries through the validator. It must not panic, and an entry it accepts must meet the rules
// the extension relies on: absolute, within the byte bound in its /private spelling, and free of ASCII control characters.
func FuzzValidateWatchedPaths(f *testing.F) {
	for _, seed := range []struct{ path, match string }{
		{"/Library/StartupItems/", "prefix"},
		{"/etc/emond.d/rules/rule.plist", "literal"},
		{"/Users/", "prefix"},
		{"/private/etc/../x", "literal"},
		{"/Users/\x00ignored/", "prefix"},
		{"", "literal"},
	} {
		f.Add(seed.path, seed.match)
	}
	f.Fuzz(func(t *testing.T, path, match string) {
		entry := WatchedPath{Path: path, Match: WatchedPathMatch(match)}
		if ValidateWatchedPaths([]WatchedPath{entry}) != nil {
			return
		}
		assert.True(t, strings.HasPrefix(path, "/"))
		assert.LessOrEqual(t, len(privateSpelling(path)), MaxWatchedPathBytes)
		assert.False(t, strings.ContainsFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }))
		assert.Contains(t, []WatchedPathMatch{WatchedPathLiteral, WatchedPathPrefix}, entry.Match)
	})
}
