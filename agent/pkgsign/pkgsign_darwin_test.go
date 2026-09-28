//go:build darwin

package pkgsign

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildPackage makes a real unsigned package with pkgbuild, which ships with macOS, then the PKInstallSandbox directory an install
// would run its scripts from. The sandbox is made after the package, as PackageKit makes it after the package exists.
func buildPackage(t *testing.T) (pkg, script string) {
	t.Helper()
	// Canonical, as PackageKit's argument is: the temp dir sits under /var, which is a symlink to /private/var.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(dir, "root")
	require.NoError(t, os.MkdirAll(root, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0o600))
	pkg = filepath.Join(dir, "test.pkg")
	out, err := exec.CommandContext(t.Context(), "/usr/bin/pkgbuild", //nolint:gosec // a fixed binary; the variable parts are paths under t.TempDir
		"--quiet", "--root", root, "--identifier", "com.example.pkgsigntest",
		"--version", "1.0", "--install-location", "/tmp/pkgsigntest", pkg).CombinedOutput()
	require.NoError(t, err, string(out))
	time.Sleep(10 * time.Millisecond) // so the sandbox's birth is strictly after the package's last change
	scripts := filepath.Join(dir, "PKInstallSandbox.test", "Scripts", "com.example.pkgsigntest.x")
	require.NoError(t, os.MkdirAll(scripts, 0o750))
	return pkg, filepath.Join(scripts, "postinstall")
}

// The case the rule most needs to get right: an answer of "unsigned", not "cannot classify".
func TestEvaluate_AnUnsignedPackage(t *testing.T) {
	t.Parallel()
	pkg, script := buildPackage(t)
	res, ok := Evaluate(pkg, script)
	require.True(t, ok, "pkgutil read the package, so this is an answer")
	assert.Equal(t, Result{}, *res)
}

// spec:endpoint-event-collection/an-installer-script-names-its-package-s-signature/a-package-changed-during-the-install-is-not-classified
//
// A preinstall that swaps a different package in at $1 must not have the swapped package's signature reported for the install.
// Any change after the sandbox was made moves the package's ctime past the sandbox's birth.
func TestEvaluate_APackageChangedDuringTheInstallIsNotClassified(t *testing.T) {
	t.Parallel()
	pkg, script := buildPackage(t)
	time.Sleep(10 * time.Millisecond)
	replacement := pkg + ".swap"
	body, err := os.ReadFile(pkg) //nolint:gosec // a path under t.TempDir
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(replacement, body, 0o600)) //nolint:gosec // a path under t.TempDir
	require.NoError(t, os.Rename(replacement, pkg))

	res, ok := Evaluate(pkg, script)
	assert.False(t, ok)
	assert.Nil(t, res)
}

// spec:endpoint-event-collection/an-installer-script-names-its-package-s-signature/a-late-read-reports-only-an-untrusted-package
//
// A script that exits at once is often read after PackageKit has removed the sandbox (captured on edr-dev, issue #1167). An
// unsigned package is still reported as unsigned: that answer cannot lend trust, and refusing it would let a package escape being
// reported unsigned by having quick scripts.
func TestEvaluate_AnUnsignedPackageReadAfterItsInstallEndedIsStillReported(t *testing.T) {
	t.Parallel()
	pkg, script := buildPackage(t)
	require.NoError(t, os.RemoveAll(filepath.Dir(filepath.Dir(filepath.Dir(script)))), "the install ended and took its sandbox")

	res, ok := Evaluate(pkg, script)
	require.True(t, ok)
	assert.Equal(t, Result{}, *res)
}

// spec:endpoint-event-collection/an-installer-script-names-its-package-s-signature/a-late-read-reports-only-an-untrusted-package
//
// The same package read as trusted is not reported once the sandbox is gone, whether pkgutil answers now or its answer is cached:
// without the sandbox nothing shows the package is the one PackageKit installed. While the sandbox stands the answer is reported.
func TestEvaluate_ATrustedPackageReadAfterItsInstallEndedIsNotReported(t *testing.T) { //nolint:paralleltest // swaps a package variable
	pkg, script := buildPackage(t)
	original := checkSignature
	t.Cleanup(func() { checkSignature = original })
	checkSignature = func(string) string { return notarizedDeveloperID }

	res, ok := Evaluate(pkg, script)
	require.True(t, ok, "while the sandbox stands a trusted answer is given")
	assert.Equal(t, Result{Signed: true, Notarized: true, TeamID: "FDG8Q7N4CC"}, *res)

	require.NoError(t, os.RemoveAll(filepath.Dir(filepath.Dir(filepath.Dir(script)))))
	res, ok = Evaluate(pkg, script)
	assert.False(t, ok, "the cached trusted answer is not given without the sandbox")
	assert.Nil(t, res)
}

// The same path holding a different file for a later install is checked again, not answered from the cache: a stale answer would
// describe the previous package. The second file is not a package at all, so a cached "unsigned" would be visibly wrong.
func TestEvaluate_ALaterFileAtTheSamePathIsCheckedAgain(t *testing.T) {
	t.Parallel()
	pkg, script := buildPackage(t)
	_, ok := Evaluate(pkg, script)
	require.True(t, ok)

	time.Sleep(10 * time.Millisecond)
	require.NoError(t, os.WriteFile(pkg, []byte("not a package"), 0o600))
	time.Sleep(10 * time.Millisecond)
	laterScripts := filepath.Join(filepath.Dir(pkg), "PKInstallSandbox.later", "Scripts", "x")
	require.NoError(t, os.MkdirAll(laterScripts, 0o750))

	res, ok := Evaluate(pkg, filepath.Join(laterScripts, "postinstall"))
	assert.False(t, ok, "pkgutil cannot read the new file, and the old package's answer must not stand in for it")
	assert.Nil(t, res)
}

func TestEvaluate_AMissingPackageCannotBeClassified(t *testing.T) {
	t.Parallel()
	_, script := buildPackage(t)
	res, ok := Evaluate(filepath.Join(t.TempDir(), "gone.pkg"), script)
	assert.False(t, ok)
	assert.Nil(t, res)
	_, ok = Evaluate("", script)
	assert.False(t, ok)
}

func TestEvaluate_AScriptOutsideASandboxCannotBeClassified(t *testing.T) {
	t.Parallel()
	pkg, _ := buildPackage(t)
	_, ok := Evaluate(pkg, "/tmp/elsewhere/postinstall")
	assert.False(t, ok, "without the sandbox there is no install start to check the package against")
}

// The window between the ctime check and pkgutil's read is closed by statting again after the read: a file replaced in between, or
// replaced and restored, is not the file that was checked.
func TestSameFile(t *testing.T) {
	t.Parallel()
	pkg, _ := buildPackage(t)
	var before syscall.Stat_t
	require.NoError(t, syscall.Stat(pkg, &before))
	var unchanged syscall.Stat_t
	require.NoError(t, syscall.Stat(pkg, &unchanged))
	assert.True(t, sameFile(before, unchanged))

	time.Sleep(10 * time.Millisecond)
	body, err := os.ReadFile(pkg) //nolint:gosec // a path under t.TempDir
	require.NoError(t, err)
	swap := pkg + ".swap"
	require.NoError(t, os.WriteFile(swap, body, 0o600)) //nolint:gosec // a path under t.TempDir
	require.NoError(t, os.Rename(swap, pkg))
	var replaced syscall.Stat_t
	require.NoError(t, syscall.Stat(pkg, &replaced))
	assert.False(t, sameFile(before, replaced), "identical bytes under a new inode are a different file")
}

// The package is swapped while pkgutil is "reading" it: the answer describes the replacement, not the package being installed, so
// it must not be reported. Not parallel: it replaces the package-level pkgutil runner.
func TestEvaluate_APackageSwappedDuringTheReadIsNotClassified(t *testing.T) { //nolint:paralleltest // swaps a package variable
	pkg, script := buildPackage(t)
	original := checkSignature
	t.Cleanup(func() { checkSignature = original })
	checkSignature = func(path string) string {
		body, err := os.ReadFile(path) //nolint:gosec // a path under t.TempDir
		require.NoError(t, err)
		swap := path + ".swap"
		require.NoError(t, os.WriteFile(swap, body, 0o600)) //nolint:gosec // a path under t.TempDir
		require.NoError(t, os.Rename(swap, path))
		return notarizedDeveloperID
	}

	res, ok := Evaluate(pkg, script)
	assert.False(t, ok, "the vendor identity pkgutil saw belongs to a file that is no longer the one checked")
	assert.Nil(t, res)
}

// A symlink in the package's path means the path was altered after PackageKit resolved it, so it no longer names the package being
// installed. The fixture puts the package behind a symlinked directory.
func TestEvaluate_APathThroughASymlinkIsNotClassified(t *testing.T) {
	t.Parallel()
	pkg, script := buildPackage(t)
	link := filepath.Join(t.TempDir(), "via-link")
	require.NoError(t, os.Symlink(filepath.Dir(pkg), link))

	res, ok := Evaluate(filepath.Join(link, filepath.Base(pkg)), script)
	assert.False(t, ok)
	assert.Nil(t, res)
}

func TestSandboxDir(t *testing.T) {
	t.Parallel()
	dir, ok := sandboxDir("/tmp/PKInstallSandbox.iJ0s6V/Scripts/com.example.x/postinstall")
	require.True(t, ok)
	assert.Equal(t, "/tmp/PKInstallSandbox.iJ0s6V", dir)
	_, ok = sandboxDir("/tmp/PKInstallSandbox.iJ0s6V")
	assert.False(t, ok)
	_, ok = sandboxDir("/tmp/other/postinstall")
	assert.False(t, ok)
}

// The cache keeps the most recent entries and forgets the oldest, and a changed file is a new key.
func TestResultCache(t *testing.T) {
	t.Parallel()
	c := &resultCache{entries: map[cacheKey]Result{}}
	first := cacheKey{path: "/a.pkg", ctime: 1, size: 1}
	c.put(first, Result{Signed: true})
	got, ok := c.get(first)
	require.True(t, ok)
	assert.True(t, got.Signed)
	_, ok = c.get(cacheKey{path: "/a.pkg", ctime: 2, size: 1})
	assert.False(t, ok, "a new ctime is a different file")

	for i := range cacheSize {
		c.put(cacheKey{path: "/b.pkg", ctime: int64(i + 10), size: 1}, Result{})
	}
	_, ok = c.get(first)
	assert.False(t, ok, "the oldest entry is evicted once the cache is full")
	assert.Len(t, c.entries, cacheSize)
}
