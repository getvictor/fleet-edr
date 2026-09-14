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

// TestWorkflow_ThePullRequestIsOpenedWithTheAppToken pins the credential wiring the tests of the step scripts cannot see. The App's
// client id and key are stored in the sigma-sync environment, not the repository, so a job that stopped naming it would read an empty
// client id. The push step must use the App's token, since a pull request opened with the workflow's own token starts no CI. And the
// token is minted only when there is something to push, with write access to contents and pull requests. The tracking issue step
// reads the push step's outputs through its env, which the script tests set directly.
func TestWorkflow_ThePullRequestIsOpenedWithTheAppToken(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(workflowPath)
	require.NoError(t, err)
	type step struct {
		ID   string            `yaml:"id"`
		Name string            `yaml:"name"`
		If   string            `yaml:"if"`
		With map[string]string `yaml:"with"`
		Env  map[string]string `yaml:"env"`
	}
	var wf struct {
		Jobs map[string]struct {
			Environment string `yaml:"environment"`
			Steps       []step `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &wf))
	job := wf.Jobs["sync"]
	assert.Equal(t, "sigma-sync", job.Environment)
	steps := map[string]step{}
	for _, s := range job.Steps {
		key := s.ID
		if key == "" {
			key = s.Name
		}
		steps[key] = s
	}
	token, push, issue := steps["app-token"], steps["push"], steps["Open, update or close the tracking issue"]
	require.NotEmpty(t, token.ID, "no app-token step")
	require.NotEmpty(t, push.ID, "no push step")
	require.NotEmpty(t, issue.Name, "no tracking issue step")
	assert.Equal(t, "${{ vars.SIGMA_SYNC_APP_CLIENT_ID }}", token.With["client-id"])
	assert.Equal(t, "${{ secrets.SIGMA_SYNC_APP_PRIVATE_KEY }}", token.With["private-key"])
	assert.Equal(t, "steps.sync.outputs.changed == 'true'", token.If)
	// Exactly these two, so a scope added later has to change this test too.
	scopes := map[string]string{}
	for input, value := range token.With {
		if strings.HasPrefix(input, "permission-") {
			scopes[input] = value
		}
	}
	assert.Equal(t, map[string]string{"permission-contents": "write", "permission-pull-requests": "write"}, scopes)
	assert.Equal(t, "${{ steps.app-token.outputs.token }}", push.Env["GH_TOKEN"])
	assert.Equal(t, "${{ github.token }}", issue.Env["GH_TOKEN"])
	assert.Equal(t, "${{ steps.sync.outputs.differs }}", issue.Env["DIFFERS"])
	assert.Equal(t, "${{ steps.sync.outputs.changed }}", issue.Env["CHANGED"])
	assert.Equal(t, "${{ steps.push.outputs.open_pr }}", issue.Env["OPEN_PR"])
	assert.Equal(t, "${{ steps.push.outputs.pr_url }}", issue.Env["PR_URL"])
}

// TestWorkflow_CIRunsTheCatalogTestsOnTheSyncPullRequest runs test.yml's change detection over the files a sync pull request changes.
// That pull request touches only rule files and generated docs, and the Go test jobs must still run, since the catalog tests that pin
// the import counts are the check the synced rules have to pass.
func TestWorkflow_CIRunsTheCatalogTestsOnTheSyncPullRequest(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../.github/workflows/test.yml")
	require.NoError(t, err)
	var wf struct {
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &wf))
	var script string
	for _, s := range wf.Jobs["changes"].Steps {
		if s.ID == "detect" {
			script = s.Run
		}
	}
	require.NotEmpty(t, script, "no detect step in test.yml")

	for name, files := range map[string]string{
		"a sync pull request": "server/rules/internal/catalog/imported/process_creation/proc_creation_macos_new.yml\n" +
			"server/rules/internal/catalog/imported/MANIFEST.sha256\ndocs/detection-rules.md\ndocs/attack-navigator-layer.json",
		"a change to the sync workflow alone": ".github/workflows/sigma-upstream-sync.yml",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newRunner(t, t.TempDir())
			writeExecutable(t, filepath.Join(r.temp, "bin", "gh"), "#!/usr/bin/env bash\nprintf '"+files+"\\n'\n")
			maps.Copy(r.env, map[string]string{"EVENT_NAME": "pull_request", "PR_NUMBER": "1", "REPO": "getvictor/fleet-edr"})
			//nolint:gosec // runs this repository's own workflow script, which is what is under test
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script)
			for k, v := range r.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Contains(t, strings.Split(r.read("out"), "\n"), "go=true", string(out))
		})
	}
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

// ghStub records each call in gh.log and answers the two list queries from FAKE_ISSUE and FAKE_PR, and pr create with createdPR.
// ON_PR_LIST, when set, is run as the pull request query is answered, to stage something happening on GitHub in that moment.
const ghStub = `#!/usr/bin/env bash
echo "gh $*" >> "$RUNNER_TEMP/gh.log"
case "$1 $2" in
  "issue list") printf '%s' "${FAKE_ISSUE:-}" ;;
  "pr list") if [ -n "${ON_PR_LIST:-}" ]; then bash -c "$ON_PR_LIST" >&2; fi; printf '%s' "${FAKE_PR:-}" ;;
  "pr create") echo "` + createdPR + `" ;;
esac
`

// createdPR is the pull request URL the gh stub reports creating.
const createdPR = "https://github.com/getvictor/fleet-edr/pull/1000"

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

// issueRunner prepares the later steps as a run that found differences would leave them: the tool's report and the test output, and,
// when the corpus changed, the catalog test section the report step writes from them. It runs in dir, a scratch directory unless a
// test needs a repository.
func issueRunner(t *testing.T, env map[string]string, testOutput string) *runner {
	t.Helper()
	return reportRunner(t, t.TempDir(), env, testOutput)
}

func reportRunner(t *testing.T, dir string, env map[string]string, testOutput string) *runner {
	t.Helper()
	r := newRunner(t, dir)
	report := "Upstream: SigmaHQ/sigma at c0ffee.\n\n## Changed rules\n"
	require.NoError(t, os.WriteFile(filepath.Join(r.temp, "report.md"), []byte(report), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(r.temp, "tests.txt"), []byte(testOutput), 0o600))
	maps.Copy(r.env, env)
	if r.env["CHANGED"] == "true" {
		out, err := r.run("report")
		require.NoError(t, err, out)
	}
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

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/upstream-changes-open-a-pull-request
func TestWorkflow_ChangesOpenAPullRequest(t *testing.T) {
	t.Parallel()
	remote, work := syncRepos(t)
	require.NoError(t, os.WriteFile(filepath.Join(work, "server/rules/internal/catalog/imported/rule.yml"), []byte("title: new\n"), 0o600))
	r := reportRunner(t, work, map[string]string{"CHANGED": "true", "TEST_EXIT": "0"}, "ok\n")
	out, err := r.run("push")
	require.NoError(t, err, out)
	assert.Equal(t, "title: new\n", gitOut(t, remote, "show", "sigma-sync/upstream:server/rules/internal/catalog/imported/rule.yml"))
	calls := r.read("gh.log")
	assert.Contains(t, calls, "gh pr create --repo getvictor/fleet-edr --base main --head sigma-sync/upstream "+
		"--title Sync vendored Sigma rules with upstream --body-file")
	assert.Contains(t, r.read("out"), "pr_url="+createdPR)
	body := r.read("pr.md")
	assert.Contains(t, body, "## Changed rules")
	assert.Contains(t, body, "`go test ./server/rules/internal/catalog/` passes.")
	assert.Contains(t, body, "actions/runs/7")

	t.Run("and an open tracking issue is closed with a link to it", func(t *testing.T) {
		t.Parallel()
		issue := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "0", "PR_URL": createdPR,
			"FAKE_ISSUE": "34"}, "ok\n")
		out, err := issue.run(issueStep)
		require.NoError(t, err, out)
		calls := issue.read("gh.log")
		assert.Contains(t, calls, "gh issue close 34 --repo getvictor/fleet-edr --comment Opened "+createdPR+" with these changes.")
		assert.NotContains(t, calls, "issue create")
		assert.NotContains(t, calls, "issue edit")
	})

	t.Run("with no issue open, nothing is filed", func(t *testing.T) {
		t.Parallel()
		issue := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "0", "PR_URL": createdPR}, "ok\n")
		out, err := issue.run(issueStep)
		require.NoError(t, err, out)
		assert.NotContains(t, issue.read("gh.log"), "gh issue close")
		assert.NotContains(t, issue.read("gh.log"), "gh issue create")
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
	assert.NotContains(t, r.read("gh.log"), "pr create", "and no second pull request is opened")

	issue := issueRunner(t, map[string]string{"DIFFERS": "true", "CHANGED": "true", "TEST_EXIT": "1", "OPEN_PR": openPR},
		"--- FAIL: TestLoadImported_TheWholeUpstreamCorpus (0.10s)\n")
	out, err = issue.run(issueStep)
	require.NoError(t, err, out)
	body := issue.read("issue.md")
	assert.Contains(t, body, "is already open, "+openPR+", and this run left it alone")
	assert.Contains(t, body, "--- FAIL: TestLoadImported_TheWholeUpstreamCorpus",
		"the test result is reported even when the branch is left alone")
}

// spec:server-detection-rules-engine/upstream-drift-is-checked-weekly/upstream-changes-open-a-pull-request
//
// With no pull request open, the push step commits the corpus and generated docs to the sync branch, creating it or replacing the
// job's previous commit on it.
func TestWorkflow_PushesTheSyncBranch(t *testing.T) { //nolint:tparallel // its subtests run in order on shared repositories
	t.Parallel()
	remote, work := syncRepos(t)
	// Sequential steps on one repository pair: the second run replaces what the first pushed.
	steps := []struct {
		name string
		rule string
	}{
		{"the first run creates the branch", "title: first\n"},
		{"a later run replaces the previous run's commit", "title: second\n"},
	}
	// Subtests in order, not parallel: each builds on the repository state the one before left.
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) { //nolint:paralleltest // sequential on shared repositories, see above
			rule := step.rule
			require.NoError(t, os.WriteFile(filepath.Join(work, "server/rules/internal/catalog/imported/rule.yml"), []byte(rule), 0o600))
			r := reportRunner(t, work, map[string]string{"CHANGED": "true", "TEST_EXIT": "0"}, "ok\n")
			out, err := r.run("push")
			require.NoError(t, err, out)
			assert.Equal(t, rule, gitOut(t, remote, "show", "sigma-sync/upstream:server/rules/internal/catalog/imported/rule.yml"))
			subject := gitOut(t, remote, "log", "-1", "--format=%s", "sigma-sync/upstream")
			assert.Equal(t, "Sync vendored Sigma rules with upstream", strings.TrimSpace(subject))
			assert.Equal(t, "2", strings.TrimSpace(gitOut(t, remote, "rev-list", "--count", "sigma-sync/upstream")),
				"one sync commit on main, replacing the previous run's")
			// A fresh checkout each run, as on the runner: back on main without the local sync branch.
			gitRun(t, work, "switch", "-q", "main")
			gitRun(t, work, "branch", "-q", "-D", "sigma-sync/upstream")
		})
	}
}

// A reviewer who opens a pull request and pushes to the branch while the step is checking for one is not overwritten: the step's
// lease is on the branch as it was before the check, so its push is refused.
func TestWorkflow_APushDuringTheCheckIsNotOverwritten(t *testing.T) {
	t.Parallel()
	remote, work := syncRepos(t)
	// A previous run's branch, which a reviewer then pushes to while the step asks GitHub for open pull requests.
	gitRun(t, work, "push", "-q", remote, "main:refs/heads/sigma-sync/upstream")
	reviewer := filepath.Join(t.TempDir(), "reviewer")
	gitRun(t, filepath.Dir(reviewer), "clone", "-q", "-b", "sigma-sync/upstream", remote, reviewer)
	require.NoError(t, os.WriteFile(filepath.Join(reviewer, "docs/detection-rules.md"), []byte("# Updated by a reviewer\n"), 0o600))
	gitRun(t, reviewer, "-c", "user.name=r", "-c", "user.email=r@example.com", "commit", "-q", "--no-verify", "-am", "reviewer")
	reviewed := strings.TrimSpace(gitOut(t, reviewer, "rev-parse", "HEAD"))

	require.NoError(t, os.WriteFile(filepath.Join(work, "server/rules/internal/catalog/imported/rule.yml"), []byte("title: new\n"), 0o600))
	r := newRunner(t, work)
	r.env["ON_PR_LIST"] = "git -C " + reviewer + " push -q origin HEAD:refs/heads/sigma-sync/upstream"
	out, err := r.run("push")
	require.Error(t, err, "the push must be refused: %s", out)
	assert.Equal(t, reviewed, strings.TrimSpace(gitOut(t, remote, "rev-parse", "sigma-sync/upstream")), "the reviewer's commit stays")
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

	reported := issueRunner(t, map[string]string{"CHANGED": "true", "TEST_EXIT": "1"}, r.read("tests.txt"))
	assert.Contains(t, reported.read("tests-section.md"), "panic: catalog: load imported", "the pull request carries the failure")
}

// The test section shows the failure lines, or the end of the output when there are none, and a long failure cannot break the step.
func TestWorkflow_TheReportCarriesTheFailingOutput(t *testing.T) {
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
			r := issueRunner(t, map[string]string{"CHANGED": "true", "TEST_EXIT": "1"}, tc.output)
			assert.Equal(t, tc.want, block(r.read("tests-section.md")))
		})
	}

	t.Run("5000 failure lines are cut to 60 without a broken pipe", func(t *testing.T) {
		t.Parallel()
		r := issueRunner(t, map[string]string{"CHANGED": "true", "TEST_EXIT": "1"},
			strings.Repeat("    --- FAIL: TestCase (0.00s)\n", 5000))
		assert.Equal(t, 60, strings.Count(block(r.read("tests-section.md")), "\n"))
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
