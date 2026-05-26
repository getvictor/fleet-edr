package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
)

// resolveRepoPath promotes a relative CLI path to its repo-root-relative form when cwd doesn't have it. The intent is
// that `spectrace check` (with its `--specs-dir openspec/specs` and `--root .` defaults) keeps working when invoked
// from a subdirectory like `tools/spectrace/` — Copilot raised the concern on PR #281. The resolution rules, in order:
//
//  1. Absolute path: returned verbatim. The user has been explicit, honour them.
//  2. Path exists relative to cwd: returned verbatim. This preserves the historical behaviour for callers who pass
//     `--specs-dir=../../openspec/specs` from inside a nested package; we don't second-guess paths that already work.
//  3. We can find a repo top-level AND the path exists relative to it: return the joined `<repoRoot>/<path>`.
//  4. Otherwise: return the original. The downstream ParseAllSpecs / ScanMarkers calls then produce a deterministic
//     "no such file or directory" error pointed at the user's input, which is the right shape for diagnosing typos.
//
// The git subprocess inherits the same 30s cap as the --new-code path so a hung lookup can't stall the linter.
func resolveRepoPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()
	root, err := gitTopLevel(ctx)
	if err != nil {
		return p
	}
	candidate := filepath.Join(root, p)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return p
}

// resolveDefaultRepoPath is the variant used for unset CLI flags. When a flag is at its default value, the user has not
// asked for "literally cwd"; they've asked for "the natural location of this thing." For the `--root .` default that
// means "the repo's source tree," not "this particular subdirectory I happen to be in." So we always try the repo top-
// level first and only fall back to the cwd-relative form when no repo top-level can be found. This matters for the
// `--root` default specifically (cwd-relative `.` exists, so resolveRepoPath would short-circuit at step 2 and leave
// the scan scoped to a tools/ subdir, missing everything else).
func resolveDefaultRepoPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()
	root, err := gitTopLevel(ctx)
	if err == nil {
		candidate := filepath.Join(root, p)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return p
}

// resolvePathFlag picks the right resolver based on whether the operator supplied the flag explicitly. Explicit values stay
// cwd-first (so `--specs-dir=./local-fixture` honours the literal `.`); default values bind to the repo root when one can be found.
// The fs.Visit walk happens once per subcommand after Parse, so the caller passes the resulting set in here as isUserSet.
func resolvePathFlag(value string, isUserSet bool) string {
	if isUserSet {
		return resolveRepoPath(value)
	}
	return resolveDefaultRepoPath(value)
}

// userSetFlagNames returns the names of every flag the operator supplied on the command line. flag.FlagSet.Visit walks only the set
// flags, which is exactly the information resolvePathFlag needs to choose between cwd-relative and repo-root resolution.
func userSetFlagNames(fs *flag.FlagSet) map[string]bool {
	out := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { out[f.Name] = true })
	return out
}
