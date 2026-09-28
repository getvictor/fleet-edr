//go:build darwin

package pkgsign

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// checkTimeout bounds one pkgutil run. A local check takes about 0.2 s, and the run sits on the agent's event path, so the bound
// is kept tight: a package that cannot be read in time is left unclassified rather than holding events back.
const checkTimeout = 2 * time.Second

// Evaluate reads the signature of the package at pkgPath, for the installer script at scriptPath. ok is false when the answer
// cannot be trusted to describe the package PackageKit is installing, and then the event carries no package signature:
//
//   - the package cannot be read (absent, or gone before the check);
//   - the package was changed after PackageKit set up the install sandbox the script runs from. The check runs after the script
//     has started, so an unsigned package's preinstall could otherwise swap a notarized vendor package in at the same path and
//     have its own postinstall reported as the vendor's. A file's ctime is set by the kernel on any write or rename and cannot be
//     set back, so a package whose ctime is not older than the sandbox is one that changed during the install;
//   - the package changed while pkgutil was reading it. The file is statted again after the read and must be the same inode with
//     the same ctime and size, so a swap between the check above and pkgutil's open cannot lend the answer a different package.
//     Swapping the original back afterwards does not help either, since that is itself a change and moves the ctime again;
//   - the path no longer resolves to itself. PackageKit hands a script the package's canonical path (a package installed from
//     /tmp arrives as /private/tmp/...), so a symlink anywhere in it was put there after the install began;
//   - the sandbox is already gone and the package reads as trusted. PackageKit removes the sandbox when the install ends, and a
//     script that exits at once is often read after that (issue #1167). Without the sandbox there is nothing to prove the package
//     unchanged, so only an answer that cannot lend trust is given: untrusted or unsigned. Refusing that too would let a package
//     escape being reported unsigned by having quick scripts.
//
// Not closed: a root-run preinstall renaming a DIRECTORY in the path so it leads to an older, genuinely signed package, whose own
// ctime predates the sandbox. Catching that would mean rejecting any ancestor changed after the sandbox, and a directory's ctime
// moves whenever a file is added to it, so packages delivered through /tmp or ~/Downloads would almost never be classified. The
// consumer is told so: this signature may only ever narrow an alert an operator chose to exclude, never raise trust on its own.
func Evaluate(pkgPath, scriptPath string) (*Result, bool) {
	if pkgPath == "" {
		return nil, false
	}
	if resolved, err := filepath.EvalSymlinks(pkgPath); err != nil || resolved != pkgPath {
		return nil, false
	}
	var pkg syscall.Stat_t
	if err := syscall.Stat(pkgPath, &pkg); err != nil {
		return nil, false
	}
	sandbox, ok := sandboxDir(scriptPath)
	if !ok {
		return nil, false
	}
	var box syscall.Stat_t
	sandboxErr := syscall.Stat(sandbox, &box)
	switch {
	case sandboxErr == nil:
		if !before(pkg.Ctimespec, box.Birthtimespec) {
			return nil, false
		}
	case !errors.Is(sandboxErr, syscall.ENOENT):
		return nil, false
	}
	key := cacheKey{path: pkgPath, dev: uint64(pkg.Dev), ino: pkg.Ino, ctime: pkg.Ctimespec.Nano(), size: pkg.Size} //nolint:gosec // a device number is not negative
	if res, hit := results.get(key); hit {
		// A hit is pkgutil's answer for this exact file, so running it again could only repeat it: an answer that cannot be
		// given now is refused at once rather than checked again.
		if !vouchable(res, sandboxErr) {
			return nil, false
		}
		return &res, true
	}
	res, ok := Parse(checkSignature(pkgPath))
	if !ok {
		return nil, false
	}
	var after syscall.Stat_t
	if err := syscall.Stat(pkgPath, &after); err != nil || !sameFile(pkg, after) {
		return nil, false
	}
	results.put(key, res)
	if !vouchable(res, sandboxErr) {
		return nil, false
	}
	return &res, true
}

// vouchable reports whether res may be given for the install. With the sandbox gone (sandboxErr set) nothing shows the package is
// the one PackageKit installed, and a trusted answer is the one a swap would be after. An untrusted answer needs no such proof: it
// can only keep an alert, never waive one.
func vouchable(res Result, sandboxErr error) bool {
	return sandboxErr == nil || !res.Signed
}

// checkSignature runs pkgutil on the package and returns its output. A variable so a test can change the file mid-read, which is
// the race the second stat exists for and cannot otherwise be timed.
var checkSignature = func(pkgPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	// pkgutil exits non-zero for an unsigned package, which is an answer rather than a failure, so the exit status is ignored
	// and the output decides.
	out, _ := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--check-signature", pkgPath).CombinedOutput() //nolint:gosec // fixed binary; the path is one argument, not a shell string
	return string(out)
}

// sameFile reports whether two stats of one path describe the same, unchanged file.
func sameFile(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Ctimespec.Nano() == b.Ctimespec.Nano()
}

// sandboxDir is the PKInstallSandbox directory an installer script runs from, which PackageKit creates before any script runs.
func sandboxDir(scriptPath string) (string, bool) {
	i := strings.Index(scriptPath, "/PKInstallSandbox.")
	if i < 0 {
		return "", false
	}
	rest := scriptPath[i+1:]
	end := strings.IndexByte(rest, '/')
	if end < 0 {
		return "", false
	}
	return scriptPath[:i+1+end], true
}

func before(a, b syscall.Timespec) bool { return a.Nano() < b.Nano() }

// cacheKey names one version of a package: the same path with a new inode, ctime or size is a different file and is checked again.
// The inode is what makes that exact: ctime is a timestamp, so two files can in principle share one.
type cacheKey struct {
	path  string
	dev   uint64
	ino   uint64
	ctime int64
	size  int64
}

// resultCache remembers recent answers so an install runs pkgutil once per package rather than once per script: every script of
// a product archive names the same outer package. Small, because installs are rare and only the current one is worth keeping.
type resultCache struct {
	mu      sync.Mutex
	entries map[cacheKey]Result
	order   []cacheKey
}

const cacheSize = 16

var results = &resultCache{entries: map[cacheKey]Result{}}

func (c *resultCache) get(k cacheKey) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.entries[k]
	return r, ok
}

func (c *resultCache) put(k cacheKey, r Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[k]; ok {
		return
	}
	if len(c.order) == cacheSize {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
	c.entries[k] = r
	c.order = append(c.order, k)
}
