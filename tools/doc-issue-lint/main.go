// Command doc-issue-lint fails when a public-facing doc references a GitHub issue or pull request that is not an OPEN issue.
//
// Public docs describe the product as it is. Explaining how it got there ("until issue #N this rule also...", "#N moved the
// check into...") is history, and history belongs in CHANGELOG.md. A link to an open issue is fine: it tells a reader about a
// known gap that is still being worked on. So every reference in scope must resolve to an issue whose state is OPEN; a closed
// issue, any pull request (open or merged), and a number that does not exist are all findings. A reference that was fine when it
// was written becomes a finding once its issue closes, which is the point: closing the issue changed the product, so the doc
// that pointed at it needs rewording.
//
// Scope (see inScope): the operator-facing docs, the OpenAPI spec and ATT&CK layer, and the rule pack files operators read in
// the console. Contributor docs, ADRs, and CHANGELOG.md are out of scope because recording history is their job.
//
// With file arguments it lints those paths; with none it reads a NUL-delimited file list from stdin (the Taskfile and CI pipe
// `git ls-files -z` into it, so untracked local drafts are never scanned). Paths outside the public scope are skipped either way.
// Issue states come from the GitHub GraphQL API, authenticated by GITHUB_TOKEN, then GH_TOKEN, then `gh auth token`. A lookup
// failure exits non-zero: the gate never passes on data it could not fetch.
//
// Run via `task lint:docs:issues`; CI runs it in .github/workflows/md-lint.yml on every pull request and daily.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// maxLineBytes bounds the bufio.Scanner buffer. proseWrap: never makes Markdown paragraphs single long lines, and the generated
// detection-rules.md carries long table rows, so the default 64 KB token cap is raised well past any realistic line.
const maxLineBytes = 4 * 1024 * 1024

// lookupTimeout bounds the whole GitHub lookup, so a hung connection fails the gate instead of stalling CI.
const lookupTimeout = 2 * time.Minute

const defaultRepo = "getvictor/fleet-edr"

// Exit codes: findings and operational errors are distinguishable to a caller.
const (
	exitFindings = 1
	exitError    = 2
)

// publicRootFiles are the repo-root files a deploying operator reads.
var publicRootFiles = []string{"README.md", "SECURITY.md", "docker-compose.prod.README.md"}

// publicDataFiles are non-Markdown public docs: the served API spec and the published ATT&CK Navigator layer.
var publicDataFiles = []string{"docs/api/openapi.yaml", "docs/attack-navigator-layer.json"}

// rulePackDir holds one rule file per detection. Operators read these as the rule's source in the console, so their prose and
// comments are public.
const rulePackDir = "server/rules/internal/catalog/pack"

// internalDocPrefixes and internalDocFiles are the docs/ Markdown files that are NOT public. Everything else under docs/ is in
// scope by default, so a new doc is checked unless someone deliberately lists it here.
var (
	// ADRs record why a decision was made at the time, and the maintenance log records what was done when: history is their job.
	internalDocPrefixes = []string{"docs/adr/", "docs/maintenance/"}

	internalDocFiles = map[string]bool{
		// Release and QA runbooks are for the people cutting a release, and name the issue a step exists because of.
		"docs/release-checklist.md": true,
		"docs/qa-rc-vm-runbook.md":  true,
		// Engineering references for contributors: test strategy, Go conventions, and debugging lessons learned the hard way.
		"docs/testing-strategy.md":    true,
		"docs/go-conventions.md":      true,
		"docs/lessons-and-gotchas.md": true,
		// Engineering self-assessments track gaps and the work that closed them.
		"docs/architecture-maturity.md": true,
		"docs/best-practices.md":        true,
		// Contributor process docs describe how the docs and the rule pack are maintained, not the product.
		"docs/doc-versioning.md": true,
		"docs/rules/README.md":   true,
	}
)

// inScope reports whether path (repo-relative, slash-separated) is a public-facing doc this gate checks.
func inScope(p string) bool {
	if slices.Contains(publicRootFiles, p) || slices.Contains(publicDataFiles, p) {
		return true
	}
	if path.Dir(p) == rulePackDir && path.Ext(p) == ".yml" {
		return true
	}
	if !strings.HasPrefix(p, "docs/") || path.Ext(p) != ".md" {
		return false
	}
	for _, prefix := range internalDocPrefixes {
		if strings.HasPrefix(p, prefix) {
			return false
		}
	}
	return !internalDocFiles[p]
}

// ref is one issue or pull request number referenced at a file and line.
type ref struct {
	path   string
	line   int
	number int
}

// issueNumber is 1 to 5 digits with no leading zero. The trailing \b means a longer digit run, or digits running into letters
// (a hex color such as #31a354 or #000000), does not match at all rather than matching a prefix.
const issueNumber = `([1-9][0-9]{0,4})\b`

// refPatterns finds references for one repository.
type refPatterns struct {
	bare      *regexp.Regexp // #N, with the preceding character checked in code (RE2 has no lookbehind)
	qualified *regexp.Regexp // owner/repo#N
	url       *regexp.Regexp // github.com/owner/repo/issues/N or /pull/N
}

func newRefPatterns(repo string) refPatterns {
	quoted := regexp.QuoteMeta(repo)
	return refPatterns{
		bare:      regexp.MustCompile(`#` + issueNumber),
		qualified: regexp.MustCompile(quoted + `#` + issueNumber),
		url:       regexp.MustCompile(`github\.com/` + quoted + `/(?:issues|pull)/` + issueNumber),
	}
}

// bareRefAllowed reports whether a bare #N at byte offset start of line is an issue reference. A preceding word character means
// a qualified reference to some repository (owner/repo#N, handled separately for ours) or an identifier; a preceding & is an HTML
// entity; a preceding / is a URL fragment.
func bareRefAllowed(line string, start int) bool {
	if start == 0 {
		return true
	}
	c := line[start-1]
	isWord := c == '_' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
	return !isWord && c != '&' && c != '/'
}

// extractRefs returns every reference in data, in line order.
func (p refPatterns) extractRefs(filePath string, data []byte) ([]ref, error) {
	var refs []ref
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		add := func(digits string) {
			n, _ := strconv.Atoi(digits) // the pattern admits only 1 to 5 decimal digits
			refs = append(refs, ref{path: filePath, line: lineNo, number: n})
		}
		for _, m := range p.bare.FindAllStringSubmatchIndex(line, -1) {
			if bareRefAllowed(line, m[0]) {
				add(line[m[2]:m[3]])
			}
		}
		for _, m := range p.qualified.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
		for _, m := range p.url.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", filePath, err)
	}
	return refs, nil
}

// itemKind is the GraphQL __typename of a resolved number.
type itemKind string

const (
	kindIssue       itemKind = "Issue"
	kindPullRequest itemKind = "PullRequest"
)

const stateOpen = "OPEN"

// item is what a number resolved to. A number absent from the lookup result does not exist in the repository.
type item struct {
	kind  itemKind
	state string
	title string
}

// stateLookup resolves issue and pull request numbers. The GitHub implementation is in github.go; tests use a map.
type stateLookup interface {
	lookup(ctx context.Context, numbers []int) (map[int]item, error)
}

// findings classifies refs against resolved states and returns one message per reference that is not an open issue.
func findings(refs []ref, states map[int]item) []string {
	var out []string
	for _, r := range refs {
		it, ok := states[r.number]
		var problem string
		switch {
		case !ok:
			problem = fmt.Sprintf("#%d does not exist in this repository", r.number)
		case it.kind == kindIssue && it.state == stateOpen:
			continue
		case it.kind == kindPullRequest:
			problem = fmt.Sprintf("#%d is a pull request (%s): %q", r.number, strings.ToLower(it.state), it.title)
		default:
			problem = fmt.Sprintf("#%d is a %s issue: %q", r.number, strings.ToLower(it.state), it.title)
		}
		out = append(out, fmt.Sprintf("%s:%d: %s", r.path, r.line, problem))
	}
	return out
}

// uniqueNumbers returns the distinct numbers across refs, sorted, so the lookup batches are deterministic.
func uniqueNumbers(refs []ref) []int {
	nums := make([]int, 0, len(refs))
	for _, r := range refs {
		nums = append(nums, r.number)
	}
	slices.Sort(nums)
	return slices.Compact(nums)
}

// run lints paths, read from fsys (the repository root), and writes findings to stderr. It returns the process exit code.
func run(ctx context.Context, fsys fs.FS, paths []string, patterns refPatterns, lookup stateLookup, stderr io.Writer) int {
	var refs []ref
	for _, p := range paths {
		p = path.Clean(filepath.ToSlash(p))
		if !inScope(p) {
			continue
		}
		data, err := fs.ReadFile(fsys, p)
		if errors.Is(err, fs.ErrNotExist) {
			continue // a path deleted from the working tree but still in the index
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "doc-issue-lint: %v\n", err)
			return exitError
		}
		fileRefs, err := patterns.extractRefs(p, data)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "doc-issue-lint: %v\n", err)
			return exitError
		}
		refs = append(refs, fileRefs...)
	}
	if len(refs) == 0 {
		return 0
	}
	states, err := lookup.lookup(ctx, uniqueNumbers(refs))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "doc-issue-lint: resolving issue states: %v\n", err)
		return exitError
	}
	found := findings(refs, states)
	if len(found) == 0 {
		return 0
	}
	for _, f := range found {
		_, _ = fmt.Fprintln(stderr, f)
	}
	_, _ = fmt.Fprintf(stderr,
		"::error::%d reference(s) above point at something other than an open issue. Public docs describe the product as it is: "+
			"describe the current behavior instead of how it changed, and link only open issues. History belongs in CHANGELOG.md.\n",
		len(found))
	return exitFindings
}

func readPathsFromStdin() ([]string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	var files []string
	for b := range bytes.SplitSeq(data, []byte{0}) {
		if len(b) > 0 {
			files = append(files, string(b))
		}
	}
	return files, nil
}

func main() {
	repo := flag.String("repo", defaultRepo, "GitHub repository (owner/name) whose issue numbers the docs reference")
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		var err error
		paths, err = readPathsFromStdin()
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "doc-issue-lint:", err)
			os.Exit(exitError)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	// Wiring boundary: the credential comes from the environment here and is passed down (issue #172). CI sets GITHUB_TOKEN; a
	// developer shell may set GH_TOKEN; with neither, the lookup falls back to `gh auth token`.
	envToken := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")) //nolint:forbidigo // wiring site, see above
	if envToken == "" {
		envToken = strings.TrimSpace(os.Getenv("GH_TOKEN")) //nolint:forbidigo // wiring site, see above
	}
	code := run(ctx, os.DirFS("."), paths, newRefPatterns(*repo), newGitHubLookup(*repo, envToken), os.Stderr)
	cancel()
	os.Exit(code)
}
