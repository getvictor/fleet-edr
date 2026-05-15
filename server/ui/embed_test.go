package ui

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFS(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "defaults to embedded when env unset",
			run: func(t *testing.T) {
				t.Helper()
				t.Setenv(LiveDirEnv, "")
				got, err := FS()
				require.NoError(t, err)
				// Assert the embedded subtree is readable, not the presence of any
				// specific file: CI seeds server/ui/dist with .gitkeep only before
				// running server tests, so checking for index.html would couple this
				// unit test to a built UI bundle that doesn't exist in CI.
				entries, err := fs.ReadDir(got, ".")
				require.NoError(t, err)
				require.NotEmpty(t, entries, "embedded FS should expose at least one entry")
			},
		},
		{
			name: "live dir override reads from disk",
			run: func(t *testing.T) {
				t.Helper()
				dir := t.TempDir()
				want := []byte("<!doctype html><html><body>live</body></html>")
				require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), want, 0o600))

				t.Setenv(LiveDirEnv, dir)
				got, err := FS()
				require.NoError(t, err)
				data, err := fs.ReadFile(got, "index.html")
				require.NoError(t, err)
				require.Equal(t, want, data)
			},
		},
		{
			name: "live dir reflects on-disk rewrites",
			run: func(t *testing.T) {
				t.Helper()
				// Property the dev workflow depends on: an FS opened once must
				// observe later writes to the underlying directory. Without this,
				// a server boot that reads index.html once would never see
				// `task build:ui` rebuilds.
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("v1"), 0o600))
				t.Setenv(LiveDirEnv, dir)

				live, err := FS()
				require.NoError(t, err)
				first, err := fs.ReadFile(live, "index.html")
				require.NoError(t, err)
				require.Equal(t, []byte("v1"), first)

				require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("v2"), 0o600))
				second, err := fs.ReadFile(live, "index.html")
				require.NoError(t, err)
				require.Equal(t, []byte("v2"), second, "FS must honour on-disk rewrites for `task build:ui` to take effect without restart")
			},
		},
		{
			name: "errors at boot when live dir does not exist",
			run: func(t *testing.T) {
				t.Helper()
				// Bad EDR_UI_LIVE_DIR previously surfaced as generic per-request
				// 500s. The os.Stat check in FS() means the dev server fails to
				// boot with a clear message instead.
				missing := filepath.Join(t.TempDir(), "does-not-exist")
				t.Setenv(LiveDirEnv, missing)

				_, err := FS()
				require.Error(t, err)
				require.ErrorIs(t, err, os.ErrNotExist)
				require.Contains(t, err.Error(), LiveDirEnv)
				require.Contains(t, err.Error(), missing)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}
