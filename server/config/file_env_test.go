package config

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileBackedGetenv_FileWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("real-secret\n"), 0o600))

	base := func(k string) string {
		switch k {
		case "EDR_ENROLL_SECRET":
			return "" // not set in env
		case "EDR_ENROLL_SECRET_FILE":
			return path
		}
		return ""
	}
	get := fileBackedGetenv(base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Equal(t, "real-secret", get("EDR_ENROLL_SECRET"),
		"empty env + _FILE set must read the file (trimming trailing newline)")
}

func TestFileBackedGetenv_DirectEnvBeatsFile(t *testing.T) {
	base := func(k string) string {
		switch k {
		case "EDR_ENROLL_SECRET":
			return "env-wins"
		case "EDR_ENROLL_SECRET_FILE":
			return "/does/not/exist"
		}
		return ""
	}
	get := fileBackedGetenv(base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Equal(t, "env-wins", get("EDR_ENROLL_SECRET"),
		"a real env var wins; _FILE path is never touched")
}

func TestFileBackedGetenv_NeitherSetReturnsEmpty(t *testing.T) {
	base := func(string) string { return "" }
	get := fileBackedGetenv(base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Empty(t, get("EDR_ENROLL_SECRET"))
}

func TestFileBackedGetenv_MissingFileLogsAndReturnsEmpty(t *testing.T) {
	// A _FILE pointing at a missing path must not crash the caller; the existing
	// required-var validator then reports "required env var X is not set" with the
	// canonical error message the operator expects.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	base := func(k string) string {
		if k == "EDR_ENROLL_SECRET_FILE" {
			return filepath.Join(t.TempDir(), "missing")
		}
		return ""
	}
	get := fileBackedGetenv(base, logger)
	assert.Empty(t, get("EDR_ENROLL_SECRET"))
	assert.Contains(t, buf.String(), "failed to read *_FILE env var")
}

// TestFileBackedGetenv_NilLoggerUsesDefault locks in the safe-fallback path so
// callers (e.g. early bootstrap code that hasn't built a logger yet) can pass
// nil and still get a working decorator. Drives the missing-_FILE branch
// specifically — that branch is the only one that exercises the nil-logger
// fallback (`logger.WarnContext` would panic on a nil logger if the fallback
// weren't applied), so a regression there must be observable in this test.
func TestFileBackedGetenv_NilLoggerUsesDefault(t *testing.T) {
	base := func(k string) string {
		if k == "EDR_ENROLL_SECRET_FILE" {
			return filepath.Join(t.TempDir(), "missing")
		}
		return ""
	}
	get := fileBackedGetenv(base, nil)
	assert.NotPanics(t, func() { _ = get("EDR_ENROLL_SECRET") })
	assert.Empty(t, get("EDR_ENROLL_SECRET"))
}

// TestWriteSecretFile drives the small helper that compose-fixture tests use to
// stage a docker-secret-style file. We assert the content is written verbatim
// and the perms are 0600 (the rest of the security model assumes secrets are
// not world-readable).
func TestWriteSecretFile(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteSecretFile(dir, "enroll-secret", "supersecret\n")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "enroll-secret"), path)

	got, err := os.ReadFile(path) //nolint:gosec // path produced by the helper under test
	require.NoError(t, err)
	assert.Equal(t, "supersecret\n", string(got))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteSecretFile_BadDir(t *testing.T) {
	// Pointing at a path under a non-existent parent surfaces the os.WriteFile
	// error rather than swallowing it — operators tracing config issues need to
	// see the path-not-found error verbatim.
	_, err := WriteSecretFile(filepath.Join(t.TempDir(), "missing-dir"), "x", "v")
	require.Error(t, err)
}

func TestFileBackedGetenv_TrimsOnlyOuterWhitespace(t *testing.T) {
	// Docker secrets often trail a newline. We strip leading + trailing whitespace
	// but preserve interior characters. A DSN like
	//   root:pw 1@tcp(mysql:3306)/edr
	// must survive with its embedded space intact.
	dir := t.TempDir()
	path := filepath.Join(dir, "dsn")
	require.NoError(t, os.WriteFile(path, []byte(
		"\nroot:pw 1@tcp(mysql:3306)/edr?parseTime=true\n\n"), 0o600))
	base := func(k string) string {
		if k == "EDR_DSN_FILE" {
			return path
		}
		return ""
	}
	get := fileBackedGetenv(base, slog.New(slog.NewTextHandler(io.Discard, nil)))
	got := get("EDR_DSN")
	assert.True(t, strings.HasPrefix(got, "root:pw 1@tcp"))
	assert.NotContains(t, got, "\n")
}
