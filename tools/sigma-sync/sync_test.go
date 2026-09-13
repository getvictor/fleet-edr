package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUpstream is an in-memory snapshot. corrupt names a path whose download returns different bytes than its blob id promises.
type fakeUpstream struct {
	files   map[string][]byte
	corrupt string
}

func (f fakeUpstream) Snapshot(context.Context) (string, []treeEntry, error) {
	entries := make([]treeEntry, 0, len(f.files))
	for p, content := range f.files {
		entries = append(entries, treeEntry{Path: p, BlobSHA: gitBlobSHA(content)})
	}
	return "c0ffee", entries, nil
}

func (f fakeUpstream) File(_ context.Context, commit, repoPath string) ([]byte, error) {
	if commit != "c0ffee" {
		return nil, fmt.Errorf("read at %s, not the snapshot's commit", commit)
	}
	if repoPath == f.corrupt {
		return []byte("tampered"), nil
	}
	content, ok := f.files[repoPath]
	if !ok {
		return nil, errors.New("not found")
	}
	return content, nil
}

// vendor writes files into a fresh vendored tree with its manifest, as the repository holds it.
func vendor(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, content := range files {
		dst := filepath.Join(dir, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o750))
		require.NoError(t, os.WriteFile(dst, []byte(content), 0o600))
	}
	require.NoError(t, writeManifest(dir))
	return dir
}

func read(t *testing.T, dir, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p))) //nolint:gosec // a test's own temporary tree.
	require.NoError(t, err)
	return string(b)
}

func TestGitBlobSHA_IsGitsID(t *testing.T) {
	t.Parallel()
	// `printf 'hello\n' | git hash-object --stdin`
	assert.Equal(t, "ce013625030ba8dba906f756967f9e9ca394464a", gitBlobSHA([]byte("hello\n")))
	assert.Equal(t, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", gitBlobSHA(nil), "the empty blob")
}

func TestLocalPathFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		repoPath, want string
		ok             bool
	}{
		{"rules/macos/process_creation/proc_creation_macos_applescript.yml", "process_creation/proc_creation_macos_applescript.yml", true},
		{"rules-threat-hunting/macos/file/file_event/x.yml", "file_event/x.yml", true},
		{"rules-emerging-threats/2026/Malware/macos/process_creation/y.yml", "process_creation/y.yml", true},
		{"rules-dfir/macos/process_creation/z.yml", "process_creation/z.yml", true},
		{"rules/windows/process_creation/w.yml", "", false},
		{"deprecated/macos/proc_creation_macos_add_to_admin_group.yml", "", false},
		{"unsupported/macos/process_creation/u.yml", "", false},
		{"rules/macos/process_creation/README.md", "", false},
		{"rules/macos/x.yml", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.repoPath, func(t *testing.T) {
			t.Parallel()
			got, ok := localPathFor(tc.repoPath)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// spec:server-detection-rules-engine/the-vendored-corpus-is-compared-with-upstream/a-corpus-that-matches-upstream-changes-nothing
func TestRun_ACorpusMatchingUpstreamChangesNothing(t *testing.T) {
	t.Parallel()
	dir := vendor(t, map[string]string{"process_creation/a.yml": "title: a\n"})
	before := read(t, dir, manifestName)
	src := fakeUpstream{files: map[string][]byte{
		"rules/macos/process_creation/a.yml":   []byte("title: a\n"),
		"rules/windows/process_creation/b.yml": []byte("title: b\n"),
	}}

	require.NoError(t, run(t.Context(), src, dir, false, ""))
	require.NoError(t, run(t.Context(), src, dir, true, ""))
	assert.Equal(t, before, read(t, dir, manifestName))
}

// spec:server-detection-rules-engine/the-vendored-corpus-is-compared-with-upstream/new-and-changed-upstream-rules-are-copied-verbatim
// spec:server-detection-rules-engine/the-vendored-corpus-is-compared-with-upstream/a-rule-withdrawn-upstream-is-reported-and-kept
func TestRun_CopiesNewAndChangedRulesVerbatimAndKeepsWithdrawnOnes(t *testing.T) {
	t.Parallel()
	dir := vendor(t, map[string]string{
		"process_creation/same.yml":    "title: same\n",
		"process_creation/changed.yml": "title: old\n",
		"process_creation/gone.yml":    "title: gone\n",
		"process_creation/retired.yml": "title: retired\n",
	})
	changed := "title: new\r\ndetection:  {}   \n" // odd whitespace and CRLF, which a verbatim copy must keep
	src := fakeUpstream{files: map[string][]byte{
		"rules/macos/process_creation/same.yml":                   []byte("title: same\n"),
		"rules/macos/process_creation/changed.yml":                []byte(changed),
		"rules-threat-hunting/macos/file/file_event/hunting.yml":  []byte("title: hunting"),
		"deprecated/macos/retired.yml":                            []byte("title: retired\n"),
		"rules-threat-hunting/windows/process_creation/other.yml": []byte("title: other\n"),
	}}

	err := run(t.Context(), src, dir, false, "")
	require.ErrorIs(t, err, errOutOfDate, "a check reports differences without changing anything")
	assert.Equal(t, "title: old\n", read(t, dir, "process_creation/changed.yml"))

	reportPath := filepath.Join(t.TempDir(), "report.md")
	require.NoError(t, run(t.Context(), src, dir, true, reportPath))

	assert.Equal(t, changed, read(t, dir, "process_creation/changed.yml"))
	assert.Equal(t, "title: hunting", read(t, dir, "file_event/hunting.yml"), "a rule tree beyond rules/ is vendored under its category")
	assert.Equal(t, "title: gone\n", read(t, dir, "process_creation/gone.yml"), "a withdrawn rule is not deleted")
	assert.Equal(t, fmt.Sprintf("%x  file_event/hunting.yml\n%x  process_creation/changed.yml\n%x  process_creation/gone.yml\n"+
		"%x  process_creation/retired.yml\n%x  process_creation/same.yml\n",
		sha256.Sum256([]byte("title: hunting")), sha256.Sum256([]byte(changed)), sha256.Sum256([]byte("title: gone\n")),
		sha256.Sum256([]byte("title: retired\n")), sha256.Sum256([]byte("title: same\n"))),
		read(t, dir, manifestName), "the manifest covers every vendored rule, withdrawn ones included")

	text := read(t, filepath.Dir(reportPath), "report.md")
	assert.Contains(t, text, "SigmaHQ/sigma at c0ffee")
	assert.Contains(t, text, "## New rules")
	assert.Contains(t, text, "`file_event/hunting.yml` from `rules-threat-hunting/macos/file/file_event/hunting.yml`")
	assert.Contains(t, text, "## Changed rules")
	assert.Contains(t, text, "`process_creation/changed.yml`")
	assert.Contains(t, text, "## Withdrawn upstream")
	assert.Contains(t, text, "`process_creation/gone.yml`: no longer among upstream's rules\n")
	assert.Contains(t, text, "`process_creation/retired.yml`: no longer among upstream's rules, moved to `deprecated/macos/retired.yml`")
	assert.NotContains(t, text, "same.yml")
}

func TestApply_WritesNothingWhenADownloadDoesNotMatchItsBlobID(t *testing.T) {
	t.Parallel()
	dir := vendor(t, map[string]string{"process_creation/a.yml": "title: a\n"})
	before := read(t, dir, manifestName)
	src := fakeUpstream{
		files: map[string][]byte{
			"rules/macos/process_creation/a.yml": []byte("title: a2\n"),
			"rules/macos/process_creation/b.yml": []byte("title: b\n"),
		},
		corrupt: "rules/macos/process_creation/b.yml",
	}

	err := run(t.Context(), src, dir, true, "")
	require.ErrorContains(t, err, "rules/macos/process_creation/b.yml: content has blob id")
	assert.Equal(t, "title: a\n", read(t, dir, "process_creation/a.yml"), "not even the download that did match is written")
	assert.NoFileExists(t, filepath.Join(dir, "process_creation", "b.yml"))
	assert.Equal(t, before, read(t, dir, manifestName))
}

func TestCompare_RefusesTwoUpstreamRulesForOneVendoredPath(t *testing.T) {
	t.Parallel()
	dir := vendor(t, map[string]string{})
	_, err := compare(dir, "c0ffee", []treeEntry{
		{Path: "rules/macos/process_creation/x.yml", BlobSHA: "1"},
		{Path: "rules-threat-hunting/macos/process_creation/x.yml", BlobSHA: "2"},
	})
	require.ErrorContains(t, err, "both map to process_creation/x.yml")
}

func TestReport_SaysWhenTheCorpusMatches(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Upstream: SigmaHQ/sigma at c0ffee.\n\nThe vendored macOS corpus matches upstream.\n", report(diff{Commit: "c0ffee"}))
}
