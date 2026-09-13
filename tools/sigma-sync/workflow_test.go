package main

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// These tests run the Sigma upstream sync workflow's own step scripts, read out of .github/workflows/sigma-upstream-sync.yml, under
// bash with the runner's -eo pipefail. gh, and go where a step builds or runs Go, are stubs on PATH that record their calls, and git
// pushes to a bare repository standing in for GitHub, so nothing reaches the network or this repository.

const workflowPath = "../../.github/workflows/sigma-upstream-sync.yml"

// workflowStep is the part of a workflow step these tests use.
type workflowStep struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	Run  string `yaml:"run"`
}

// stepScript returns the run script of the step with the given id, or, for the step without one, the given name.
func stepScript(t *testing.T, key string) string {
	t.Helper()
	raw, err := os.ReadFile(workflowPath)
	require.NoError(t, err)
	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &wf))
	for _, s := range wf.Jobs["sync"].Steps {
		if s.ID == key || s.Name == key {
			return s.Run
		}
	}
	t.Fatalf("no step %q in %s", key, workflowPath)
	return ""
}

// runner is one step's environment: a scratch RUNNER_TEMP with GITHUB_OUTPUT, stubs first on PATH, and a working directory.
type runner struct {
	t    *testing.T
	temp string
	dir  string
	env  map[string]string
}

// ghStub records each call in gh.log and answers the two list queries from FAKE_ISSUE and FAKE_PR.
const ghStub = `#!/usr/bin/env bash
echo "gh $*" >> "$RUNNER_TEMP/gh.log"
case "$1 $2" in
  "issue list") printf '%s' "${FAKE_ISSUE:-}" ;;
  "pr list") printf '%s' "${FAKE_PR:-}" ;;
esac
`

func newRunner(t *testing.T, dir string) *runner {
	t.Helper()
	temp := t.TempDir()
	bin := filepath.Join(temp, "bin")
	require.NoError(t, os.Mkdir(bin, 0o750))
	writeExecutable(t, filepath.Join(bin, "gh"), ghStub)
	require.NoError(t, os.WriteFile(filepath.Join(temp, "out"), nil, 0o600))
	return &runner{t: t, temp: temp, dir: dir, env: map[string]string{
		"RUNNER_TEMP":       temp,
		"GITHUB_OUTPUT":     filepath.Join(temp, "out"),
		"GITHUB_REPOSITORY": "getvictor/fleet-edr",
		"GITHUB_SERVER_URL": "https://github.com",
		"GITHUB_RUN_ID":     "7",
		"SYNC_BRANCH":       "sigma-sync/upstream",
		"ISSUE_TITLE":       "Vendored Sigma rules differ from upstream",
		"GH_TOKEN":          "token",
		"PATH":              bin + string(os.PathListSeparator) + os.Getenv("PATH"), //nolint:forbidigo // the step needs bash and git
	}}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o700)) //nolint:gosec // a test stub that must be executable
}

// run executes the step script and returns its combined output and error.
func (r *runner) run(key string) (string, error) {
	r.t.Helper()
	//nolint:gosec // runs this repository's own workflow script, which is what is under test
	cmd := exec.CommandContext(r.t.Context(), "bash", "-eo", "pipefail", "-c", stepScript(r.t, key))
	cmd.Dir = r.dir
	cmd.Env = []string{"HOME=" + r.temp, "GIT_CONFIG_NOSYSTEM=1"}
	for k, v := range r.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r *runner) read(name string) string {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.temp, name)) //nolint:gosec // a file the step wrote in this test's temp dir
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(r.t, err)
	return string(raw)
}

const issueStep = "Open, update or close the tracking issue"

// issueRunner prepares the issue step as a run that found differences would leave it: the tool's report and the test output.
func issueRunner(t *testing.T, env map[string]string, testOutput string) *runner {
	t.Helper()
	r := newRunner(t, t.TempDir())
	report := "Upstream: SigmaHQ/sigma at c0ffee.\n\n## Changed rules\n"
	require.NoError(t, os.WriteFile(filepath.Join(r.temp, "report.md"), []byte(report), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(r.temp, "tests.txt"), []byte(testOutput), 0o600))
	maps.Copy(r.env, env)
	return r
}

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/a-matching-corpus-changes-nothing-and-closes-the-report
func TestWorkflow_AMatchingCorpusClosesTheTrackingIssue(t *testing.T) {
	t.Parallel()
	r := issueRunner(t, map[string]string{"DIFFERS": "false", "FAKE_ISSUE": "12"}, "")
	out, err := r.run(issueStep)
	require.NoError(t, err, out)
	calls := r.read("gh.log")
	assert.Contains(t, calls, "gh issue close 12 ")
	assert.NotContains(t, calls, "issue create")
	assert.NotContains(t, calls, "issue edit")

	t.Run("and with no issue open, does nothing", func(t *testing.T) {
		t.Parallel()
		r := issueRunner(t, map[string]string{"DIFFERS": "false"}, "")
		out, err := r.run(issueStep)
		require.NoError(t, err, out)
		assert.NotContains(t, r.read("gh.log"), "issue close")
	})
}

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/upstream-changes-reach-a-review-branch-and-the-report
func TestWorkflow_ChangesAreReportedWithAPullRequestLink(t *testing.T) {
	t.Parallel()
	r := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "0"}, "ok\n")
	out, err := r.run(issueStep)
	require.NoError(t, err, out)
	assert.Contains(t, r.read("gh.log"), "gh issue create --repo getvictor/fleet-edr --title Vendored Sigma rules differ from upstream")
	body := r.read("issue.md")
	assert.Contains(t, body, "## Changed rules")
	assert.Contains(t, body, "(https://github.com/getvictor/fleet-edr/compare/main...sigma-sync/upstream?expand=1)")
	assert.Contains(t, body, "`go test ./server/rules/internal/catalog/` passes.")
	assert.Contains(t, body, "actions/runs/7")

	t.Run("an open issue is updated in place", func(t *testing.T) {
		t.Parallel()
		r := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "0", "FAKE_ISSUE": "34"}, "ok\n")
		out, err := r.run(issueStep)
		require.NoError(t, err, out)
		assert.Contains(t, r.read("gh.log"), "gh issue edit 34 ")
		assert.NotContains(t, r.read("gh.log"), "issue create")
	})
}

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/a-withdrawal-alone-is-reported-without-a-branch-change
func TestWorkflow_AWithdrawalAloneIsReportedWithoutABranch(t *testing.T) {
	t.Parallel()
	r := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "false"}, "")
	out, err := r.run(issueStep)
	require.NoError(t, err, out)
	body := r.read("issue.md")
	assert.Contains(t, body, "No vendored file changes: upstream withdrew a rule")
	assert.NotContains(t, body, "Open the pull request")
	assert.NotContains(t, body, "## Catalog tests")
}

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/a-pull-request-under-review-is-left-alone
func TestWorkflow_APullRequestUnderReviewIsLeftAlone(t *testing.T) {
	t.Parallel()
	const openPR = "https://github.com/getvictor/fleet-edr/pull/999"
	remote, work := syncRepos(t)
	r := newRunner(t, work)
	r.env["FAKE_PR"] = openPR
	out, err := r.run("push")
	require.NoError(t, err, out)
	assert.Contains(t, r.read("out"), "open_pr="+openPR)
	assert.Empty(t, gitOut(t, remote, "branch", "--list", "sigma-sync/upstream"), "nothing is pushed while a pull request is open")

	issue := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "1", "OPEN_PR": openPR},
		"--- FAIL: TestLoadImported_TheWholeUpstreamCorpus (0.10s)\n")
	out, err = issue.run(issueStep)
	require.NoError(t, err, out)
	body := issue.read("issue.md")
	assert.Contains(t, body, "is already open, "+openPR+", and this run left it alone")
	assert.NotContains(t, body, "Open the pull request")
	assert.Contains(t, body, "--- FAIL: TestLoadImported_TheWholeUpstreamCorpus",
		"the test result is reported even when the branch is left alone")
}

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/upstream-changes-reach-a-review-branch-and-the-report
//
// With no pull request open, the push step commits the corpus and generated docs to the sync branch, creating it or replacing the
// job's previous commit on it.
func TestWorkflow_PushesTheSyncBranch(t *testing.T) {
	t.Parallel()
	remote, work := syncRepos(t)
	for i, rule := range []string{"title: first\n", "title: second\n"} {
		require.NoError(t, os.WriteFile(filepath.Join(work, "server/rules/internal/catalog/imported/rule.yml"), []byte(rule), 0o600))
		r := newRunner(t, work)
		out, err := r.run("push")
		require.NoError(t, err, "run %d: %s", i, out)
		assert.Equal(t, rule, gitOut(t, remote, "show", "sigma-sync/upstream:server/rules/internal/catalog/imported/rule.yml"))
		subject := gitOut(t, remote, "log", "-1", "--format=%s", "sigma-sync/upstream")
		assert.Equal(t, "Sync vendored Sigma rules with upstream", strings.TrimSpace(subject))
		assert.Equal(t, "2", strings.TrimSpace(gitOut(t, remote, "rev-list", "--count", "sigma-sync/upstream")),
			"one sync commit on main, replacing the previous run's")
		// A fresh checkout each run, as on the runner: back on main without the local sync branch.
		gitRun(t, work, "switch", "-q", "main")
		gitRun(t, work, "branch", "-q", "-D", "sigma-sync/upstream")
	}
}

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/a-rule-that-breaks-the-corpus-is-still-reported
func TestWorkflow_ARuleThatBreaksTheCorpusIsStillReported(t *testing.T) {
	t.Parallel()
	_, work := syncRepos(t)
	r := newRunner(t, work)
	// A go that fails the docs generator after truncating its output, as a panic while loading the catalog does, and fails the tests.
	writeExecutable(t, filepath.Join(r.temp, "bin", "go"), `#!/usr/bin/env bash
if [ "$1 $2" = "run ./tools/gen-rule-docs" ]; then : > docs/detection-rules.md; echo "panic: catalog: load imported"; exit 2; fi
if [ "$1" = "test" ]; then echo "FAIL	github.com/fleetdm/edr/server/rules/internal/catalog	0.1s"; exit 1; fi
exit 0
`)
	out, err := r.run("tests")
	require.NoError(t, err, "a failing generator or test does not stop the job: %s", out)
	assert.Contains(t, r.read("out"), "exit=1")
	docs, err := os.ReadFile(filepath.Join(work, "docs/detection-rules.md")) //nolint:gosec // this test's scratch repository
	require.NoError(t, err)
	assert.Equal(t, "# Detection rules\n", string(docs), "a generator that failed does not leave a truncated file for the branch")

	issue := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "1"}, r.read("tests.txt"))
	out, err = issue.run(issueStep)
	require.NoError(t, err, out)
	assert.Contains(t, issue.read("issue.md"), "panic: catalog: load imported")
}

// The issue shows the failure lines, or the end of the output when there are none, and a long failure cannot break the step.
func TestWorkflow_TheIssueCarriesTheFailingOutput(t *testing.T) {
	t.Parallel()
	block := func(body string) string {
		_, after, found := strings.Cut(body, "```text\n")
		require.True(t, found, body)
		inside, _, found := strings.Cut(after, "```")
		require.True(t, found, body)
		return inside
	}
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{"a panic, whose bare FAIL line is not matched", "panic: boom\n\ngoroutine 1 [running]:\nFAIL\tcatalog\t0.1s\n", "panic: boom\n"},
		{"test failures", "=== RUN TestX\n    --- FAIL: TestX (0.00s)\n        \tError:      \tNot equal:\nok\n",
			"    --- FAIL: TestX (0.00s)\n        \tError:      \tNot equal:\n"},
		{"a build error with no failure lines", "main.go:3: undefined: x\nexit status 1\n", "main.go:3: undefined: x\nexit status 1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "1"}, tc.output)
			out, err := r.run(issueStep)
			require.NoError(t, err, out)
			assert.Equal(t, tc.want, block(r.read("issue.md")))
		})
	}

	t.Run("5000 failure lines are cut to 60 without a broken pipe", func(t *testing.T) {
		t.Parallel()
		r := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "1"},
			strings.Repeat("    --- FAIL: TestCase (0.00s)\n", 5000))
		out, err := r.run(issueStep)
		require.NoError(t, err, out)
		assert.Equal(t, 60, strings.Count(block(r.read("issue.md")), "\n"))
	})
}

// syncRepos makes a bare repository standing in for GitHub and a clone of it on main holding the paths the push step commits.
// git's insteadOf sends the step's github.com remote to the bare repository.
func syncRepos(t *testing.T) (remote, work string) {
	t.Helper()
	root := t.TempDir()
	remote = filepath.Join(root, "remote.git")
	work = filepath.Join(root, "work")
	gitRun(t, root, "init", "-q", "--bare", "-b", "main", remote)
	gitRun(t, root, "init", "-q", "-b", "main", work)
	for path, content := range map[string]string{
		"server/rules/internal/catalog/imported/rule.yml": "title: vendored\n",
		"docs/detection-rules.md":                         "# Detection rules\n",
		"docs/attack-navigator-layer.json":                "{}\n",
	} {
		full := filepath.Join(work, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}
	gitRun(t, work, "add", ".")
	gitRun(t, work, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--no-verify", "-m", "main")
	gitRun(t, work, "config", "url."+remote+".insteadOf", "https://github.com/getvictor/fleet-edr.git")
	gitRun(t, work, "push", "-q", remote, "main")
	return remote, work
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	gitOut(t, dir, args...)
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // fixed git subcommands on this test's scratch repositories
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return string(out)
}
