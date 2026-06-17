package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultBaseRef is the merge-base parent the --new-code gate diffs against. `origin/main` mirrors how SonarCloud frames
// "new code on this PR" against the target branch; for local runs without an origin remote, callers can pass --base-ref.
const defaultBaseRef = "origin/main"

// gitCommandTimeout caps every git subprocess this file spawns. CI typically completes git operations in well under a
// second; the timeout exists so a misconfigured environment (credential prompt, hung network fetch, etc.) can't hang the
// spectrace job indefinitely. Gemini called this out on PR #281; the cap is conservative so a legitimately slow `git diff`
// on a very large spec.md still has plenty of headroom.
const gitCommandTimeout = 30 * time.Second

// scenarioRange records the line range a canonical scenario occupies in its spec.md, used to intersect against git-diff
// hunks. The range is closed-closed in 1-based line numbers, matching git's `+a,b` hunk header convention. End is the line
// of the last body line before the next subheading or EOF; the scenario heading itself is at Start.
type scenarioRange struct {
	ID    string
	Start int
	End   int
}

// computeNewCodeScenarioIDs returns the set of canonical scenario IDs that were added or modified in the working branch
// relative to baseRef. "Modified" means at least one new-side line of the scenario's range (heading or body) appears in a
// diff hunk against the merge base of HEAD and baseRef. baseRef defaults to defaultBaseRef when empty.
//
// The returned map is empty when no spec.md file changed; that's an honest signal that --new-code has nothing to gate on
// and the caller should pass the check. If the git plumbing fails (no merge base, no git, baseRef unknown), an error is
// returned so the caller can decide whether to fail open or fail closed; runCheck fails closed (exit 2) because the
// gate's correctness depends on having a merge base.
func computeNewCodeScenarioIDs(ctx context.Context, specsDir, baseRef string) (map[string]struct{}, error) {
	if baseRef == "" {
		baseRef = defaultBaseRef
	}
	if err := validateBaseRef(baseRef); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, gitCommandTimeout)
	defer cancel()

	repoRoot, err := gitTopLevel(ctx)
	if err != nil {
		return nil, fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	mergeBase, err := gitMergeBase(ctx, repoRoot, baseRef)
	if err != nil {
		return nil, fmt.Errorf("git merge-base HEAD %s: %w", baseRef, err)
	}
	changedFiles, err := gitChangedFiles(ctx, repoRoot, mergeBase, specsDir)
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only: %w", err)
	}
	out := make(map[string]struct{})
	for _, file := range changedFiles {
		if filepath.Base(file) != "spec.md" {
			continue
		}
		if err := addTouchedScenarioIDs(ctx, out, repoRoot, mergeBase, file); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// addTouchedScenarioIDs adds to out the canonical ID of every scenario in `file` whose line range overlaps a new-side diff
// hunk against mergeBase. file is repo-root-relative as returned by gitChangedFiles; repoRoot anchors both the git diff and
// the spec.md open so spectrace works whether invoked from the repo top-level (CI shape) or a subdirectory (a contributor
// in their package).
func addTouchedScenarioIDs(ctx context.Context, out map[string]struct{}, repoRoot, mergeBase, file string) error {
	hunks, err := gitDiffNewLineRanges(ctx, repoRoot, mergeBase, file)
	if err != nil {
		return fmt.Errorf("git diff %s: %w", file, err)
	}
	ranges, err := parseSpecScenarioRanges(filepath.Join(repoRoot, file))
	if err != nil {
		return fmt.Errorf("parse %s: %w", file, err)
	}
	for _, sr := range ranges {
		if anyOverlap(sr.Start, sr.End, hunks) {
			out[sr.ID] = struct{}{}
		}
	}
	return nil
}

// validateBaseRef rejects revisions that git would interpret as command-line options instead of a commit-ish reference.
// `git merge-base HEAD --help` opens pager output and `--exec=...` style abuses become a remote-code-execution surface.
// Refnames legitimately cannot start with `-` (git refuses them on creation), so this check has no false-positive
// surface. Copilot flagged the option-injection risk on PR #281.
func validateBaseRef(baseRef string) error {
	if strings.HasPrefix(baseRef, "-") {
		return fmt.Errorf("invalid --base-ref %q: revisions starting with '-' would be parsed as git options", baseRef)
	}
	return nil
}

// gitTopLevel resolves the working copy's root so subsequent git commands run with a stable Dir. Without this, running
// spectrace from a subdirectory would pass `--specs-dir` relative to the subdirectory but `git diff -- <specsDir>` would
// resolve <specsDir> relative to the subdirectory too, which usually works but breaks if --specs-dir is absolute or the
// caller cd'd outside the worktree. Copilot called this out on PR #281.
func gitTopLevel(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel") //nolint:gosec // args are literal
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", wrapGitErr(err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// wrapGitErr attaches the trimmed combined output of a failed git subprocess to err so the caller surfaces the actionable
// git message (missing remote, shallow clone, unknown ref) instead of a bare `exit status 1`.
func wrapGitErr(err error, out []byte) error {
	return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
}

// lineRange is a closed-closed range of new-side file lines (1-based).
type lineRange struct {
	Start, End int
}

func anyOverlap(start, end int, hunks []lineRange) bool {
	for _, h := range hunks {
		if h.End >= start && h.Start <= end {
			return true
		}
	}
	return false
}

// gitMergeBase runs `git merge-base HEAD baseRef` and returns the resolved SHA. The merge-base is the right "branch point"
// reference for a SonarCloud-style new-code diff: it excludes upstream changes that landed on baseRef after the branch
// was cut, which would otherwise inflate the new-code set on a long-running branch. CombinedOutput captures stderr so a
// failure (missing remote, shallow clone) carries the actionable git error message in the returned error instead of a
// bare `exit status 1`; Gemini called this out on PR #281.
func gitMergeBase(ctx context.Context, repoRoot, baseRef string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "merge-base", "HEAD", baseRef) //nolint:gosec // baseRef passed validateBaseRef
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", wrapGitErr(err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitChangedFiles returns the list of files changed between mergeBase and the working tree, filtered to those under
// specsDir. We use `--diff-filter=ACMR` to drop deletions: a deleted scenario can't be uncovered because it's no longer
// in the canonical set, so deletions don't contribute to the gate. cmd.Dir is the repo root so specsDir resolves
// against the repo root regardless of where the caller invoked spectrace.
func gitChangedFiles(ctx context.Context, repoRoot, mergeBase, specsDir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "--diff-filter=ACMR", mergeBase, "--", specsDir) //nolint:gosec // args bounded
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapGitErr(err, out)
	}
	var files []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		files = append(files, line)
	}
	return files, nil
}

var hunkHeaderRE = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// gitDiffNewLineRanges runs `git diff --unified=0 mergeBase -- file` and parses the @@ headers to return the changed
// new-side line ranges. --unified=0 strips context so the ranges describe only added/modified lines, which is the precise
// shape the gate needs. cmd.Dir is the repo root so `file` resolves against the repo root regardless of cwd.
func gitDiffNewLineRanges(ctx context.Context, repoRoot, mergeBase, file string) ([]lineRange, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--unified=0", mergeBase, "--", file) //nolint:gosec // args bounded
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapGitErr(err, out)
	}
	return parseUnifiedDiffNewRanges(string(out)), nil
}

// parseUnifiedDiffNewRanges extracts new-side line ranges from a unified diff. A hunk header
// `@@ -<a>,<b> +<c>,<d> @@` yields the range [c, c+d-1]; missing `,d` means d=1. Hunks whose new-side count is 0 (pure
// deletion) are skipped, as their c value names the line BEFORE the deletion and doesn't intersect any scenario range in
// the new file.
func parseUnifiedDiffNewRanges(diff string) []lineRange {
	var out []lineRange
	scanner := bufio.NewScanner(strings.NewReader(diff))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		m := hunkHeaderRE.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		start, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		count := 1
		if m[2] != "" {
			count, err = strconv.Atoi(m[2])
			if err != nil {
				continue
			}
		}
		if count == 0 {
			continue
		}
		out = append(out, lineRange{Start: start, End: start + count - 1})
	}
	return out
}

// parseSpecScenarioRanges parses a spec.md and returns the line range each scenario occupies. The range starts at the
// `#### Scenario:` heading line and ends at the line BEFORE the next subheading (or EOF). The implementation mirrors
// parseSpec in spec.go but tracks Start/End instead of the Requirement/Title metadata that spec.go cares about; sharing
// the same parser was rejected because the existing parser is in a hot path and growing it to emit ranges would
// complicate the streaming flow for a feature only --new-code uses.
//
// One subtlety: the requirement-body lines BEFORE the first scenario heading need to attribute to "every scenario under
// this requirement" so a SHALL/MUST edit upstream of any scenario heading promotes all the scenarios under that
// requirement into the new-code set. We model this by extending each scenario's range BACKWARD to include the requirement
// heading + body, which means a diff hunk anywhere from the requirement heading through the scenario body counts the
// scenario as touched.
func parseSpecScenarioRanges(path string) ([]scenarioRange, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from gitChangedFiles output
	if err != nil {
		return nil, err
	}
	defer f.Close()

	specDir := filepath.Base(filepath.Dir(path))
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		ranges          []scenarioRange
		currentReqSlug  string
		currentReqStart int  // line of the active `### Requirement:` heading
		currentScenIdx  = -1 // index into ranges of the active scenario (so we can close it on the next subheading)
		lineNo          int
	)
	closeScenario := func(line int) {
		if currentScenIdx >= 0 {
			ranges[currentScenIdx].End = line - 1
			currentScenIdx = -1
		}
	}
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "### Requirement:"):
			closeScenario(lineNo)
			title := strings.TrimSpace(strings.TrimPrefix(line, "### Requirement:"))
			currentReqSlug = slugify(title)
			currentReqStart = lineNo
		case strings.HasPrefix(line, "#### Scenario:") && currentReqSlug != "":
			closeScenario(lineNo)
			title := strings.TrimSpace(strings.TrimPrefix(line, "#### Scenario:"))
			ranges = append(ranges, scenarioRange{
				ID:    specDir + "/" + currentReqSlug + "/" + slugify(title),
				Start: currentReqStart, // extend backward to include requirement heading + body
				End:   lineNo,          // tentative; updated when the next subheading or EOF is seen
			})
			currentScenIdx = len(ranges) - 1
		case strings.HasPrefix(line, "### ") || strings.HasPrefix(line, "## "):
			closeScenario(lineNo)
			currentReqSlug = ""
			currentReqStart = 0
		case strings.HasPrefix(line, "#### "):
			closeScenario(lineNo)
		}
	}
	// Final close: any scenario open at EOF ends on the last line scanned.
	closeScenario(lineNo + 1)
	return ranges, scanner.Err()
}
