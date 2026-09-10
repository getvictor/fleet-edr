package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// String comparison is the trap here: "9.0" sorts after "19.2" lexically, and ATT&CK has been through both, so a naive
// compare would report a v19 table as ahead of a v9 index and pass a stale table forever.
func TestCompareVersions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want int
	}{
		{"19.2", "19.2", 0},
		{"19.1", "19.2", -1},
		{"19.2", "19.1", 1},
		{"9.0", "19.2", -1},
		{"19.2", "9.0", 1},
		{"19", "19.0", 0},
		{"20.0", "19.2", 1},
	}
	for _, tc := range cases {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			t.Parallel()
			got, err := compareVersions(tc.a, tc.b)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCompareVersions_RejectsNonNumeric(t *testing.T) {
	t.Parallel()
	_, err := compareVersions("19.2", "v19.2")
	assert.Error(t, err, "a version that is not dotted-numeric is an error, not silently zero")
}

func TestVendoredVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "table.ts")
	require.NoError(t, os.WriteFile(path, []byte("export const ATTACK_VERSION = \"19.2\";\n"), 0o600))

	got, err := vendoredVersion(path)
	require.NoError(t, err)
	assert.Equal(t, "19.2", got)
}

// A table with no version must fail loudly. Defaulting to something would let the release check pass against a file it could
// not actually read, which is the failure mode the check exists to prevent.
func TestVendoredVersion_RequiresTheConstant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "table.ts")
	require.NoError(t, os.WriteFile(path, []byte("export const TECHNIQUE_CATALOG = {};\n"), 0o600))

	_, err := vendoredVersion(path)
	assert.Error(t, err)
}
