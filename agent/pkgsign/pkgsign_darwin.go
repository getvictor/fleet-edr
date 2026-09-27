//go:build darwin

package pkgsign

import (
	"context"
	"os/exec"
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
//     set back, so a package whose ctime is not older than the sandbox is one that changed during the install.
func Evaluate(pkgPath, scriptPath string) (*Result, bool) {
	if pkgPath == "" {
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
	if err := syscall.Stat(sandbox, &box); err != nil {
		return nil, false
	}
	if !before(pkg.Ctimespec, box.Birthtimespec) {
		return nil, false
	}
	key := cacheKey{path: pkgPath, ctime: pkg.Ctimespec.Nano(), size: pkg.Size}
	if res, hit := results.get(key); hit {
		return &res, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	// pkgutil exits non-zero for an unsigned package, which is an answer rather than a failure, so the exit status is ignored
	// and the output decides.
	out, _ := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--check-signature", pkgPath).CombinedOutput() //nolint:gosec // fixed binary; the path is one argument, not a shell string
	res, ok := Parse(string(out))
	if !ok {
		return nil, false
	}
	results.put(key, res)
	return &res, true
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

// cacheKey names one version of a package: the same path with a new ctime or size is a different file and is checked again.
type cacheKey struct {
	path  string
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
