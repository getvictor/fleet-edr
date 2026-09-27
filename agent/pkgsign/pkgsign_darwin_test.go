//go:build darwin

package pkgsign

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Evaluate against a real package, built here with pkgbuild, which ships with macOS. It is unsigned, which is the case the rule
// most needs to get right: an answer of "unsigned", not "cannot classify".
func TestEvaluate_AnUnsignedPackage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	require.NoError(t, os.MkdirAll(root, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0o600))
	pkg := filepath.Join(dir, "test.pkg")
	out, err := exec.CommandContext(t.Context(), "/usr/bin/pkgbuild", //nolint:gosec // a fixed binary; the variable parts are paths under t.TempDir
		"--quiet", "--root", root, "--identifier", "com.example.pkgsigntest",
		"--version", "1.0", "--install-location", "/tmp/pkgsigntest", pkg).CombinedOutput()
	require.NoError(t, err, string(out))

	res, ok := Evaluate(pkg)
	require.True(t, ok, "pkgutil read the package, so this is an answer")
	assert.Equal(t, Result{}, *res)
}

func TestEvaluate_AMissingPackageCannotBeClassified(t *testing.T) {
	t.Parallel()
	res, ok := Evaluate(filepath.Join(t.TempDir(), "gone.pkg"))
	assert.False(t, ok)
	assert.Nil(t, res)
	_, ok = Evaluate("")
	assert.False(t, ok)
}
