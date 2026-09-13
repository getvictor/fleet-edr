package main

import (
	"context"
	"crypto/sha1" //nolint:gosec // git's blob id is SHA-1; it identifies content upstream already hashed, it guards nothing.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// manifestName is the checksum manifest the vendored tree carries, which TestImportedCorpus_MatchesTheVendoredManifest reads.
const manifestName = "MANIFEST.sha256"

// treeEntry is one file in an upstream snapshot: its path in the repository and its git blob id.
type treeEntry struct {
	Path    string
	BlobSHA string
}

// upstream is a snapshot of the SigmaHQ repository: the files at one commit, and a file's bytes at that commit.
type upstream interface {
	Snapshot(ctx context.Context) (commit string, entries []treeEntry, err error)
	File(ctx context.Context, commit, repoPath string) ([]byte, error)
}

// upstreamRule is an upstream macOS rule and where it lives in the vendored tree.
type upstreamRule struct {
	RepoPath  string
	LocalPath string
	BlobSHA   string
}

// withdrawal is a vendored rule upstream no longer carries among its rules. Deprecated names the path upstream moved it to under
// deprecated/, when it did.
type withdrawal struct {
	LocalPath  string
	Deprecated string
}

// diff is how the vendored tree differs from an upstream snapshot.
type diff struct {
	Commit    string
	New       []upstreamRule
	Changed   []upstreamRule
	Withdrawn []withdrawal
}

func (d diff) empty() bool { return len(d.New) == 0 && len(d.Changed) == 0 && len(d.Withdrawn) == 0 }

// localPathFor maps an upstream path to its place in the vendored tree, and reports whether the path is a macOS rule at all.
//
// Every top-level rule tree counts (`rules` and any `rules-*`, such as rules-threat-hunting), and a macos directory at any depth
// within it, so a tree that gains one is noticed without a change here: rules-emerging-threats, for one, nests by year first. The
// vendored layout is flat by log-source category: the directory holding the file names it, so rules/macos/process_creation/x.yml
// and rules-threat-hunting/macos/file/file_event/y.yml land at process_creation/x.yml and file_event/y.yml, the layout the corpus
// loader walks.
func localPathFor(repoPath string) (string, bool) {
	parts := strings.Split(repoPath, "/")
	macos := slices.Index(parts, "macos")
	// The file must sit in a category directory below macos, so there are at least two more segments after it.
	if !isRuleTree(parts[0]) || macos < 1 || len(parts)-macos < 3 || path.Ext(repoPath) != ".yml" {
		return "", false
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1], true
}

func isRuleTree(name string) bool { return name == "rules" || strings.HasPrefix(name, "rules-") }

// gitBlobSHA is the id git gives content: SHA-1 over a "blob <size>" header and the bytes. Comparing it with the tree's id tells
// whether a vendored file is byte-identical to upstream without downloading the file.
func gitBlobSHA(content []byte) string {
	h := sha1.New() //nolint:gosec // see the import.
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(content))
	_, _ = h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// compare reports how the vendored tree at dir differs from the upstream snapshot.
func compare(dir, commit string, entries []treeEntry) (diff, error) {
	d := diff{Commit: commit}
	rules := map[string]upstreamRule{}
	deprecated := map[string]string{}
	for _, e := range entries {
		if parts := strings.Split(e.Path, "/"); len(parts) >= 3 && parts[0] == "deprecated" && parts[1] == "macos" {
			deprecated[path.Base(e.Path)] = e.Path
		}
		local, ok := localPathFor(e.Path)
		if !ok {
			continue
		}
		if prior, dup := rules[local]; dup {
			return diff{}, fmt.Errorf("upstream %s and %s both map to %s in the vendored tree", prior.RepoPath, e.Path, local)
		}
		rules[local] = upstreamRule{RepoPath: e.Path, LocalPath: local, BlobSHA: e.BlobSHA}
	}

	vendored, err := vendoredRules(dir)
	if err != nil {
		return diff{}, err
	}
	for local, content := range vendored {
		rule, ok := rules[local]
		switch {
		case !ok:
			d.Withdrawn = append(d.Withdrawn, withdrawal{LocalPath: local, Deprecated: deprecated[path.Base(local)]})
		case gitBlobSHA(content) != rule.BlobSHA:
			d.Changed = append(d.Changed, rule)
		}
	}
	for local, rule := range rules {
		if _, ok := vendored[local]; !ok {
			d.New = append(d.New, rule)
		}
	}
	slices.SortFunc(d.New, byLocalPath)
	slices.SortFunc(d.Changed, byLocalPath)
	slices.SortFunc(d.Withdrawn, func(a, b withdrawal) int { return strings.Compare(a.LocalPath, b.LocalPath) })
	return d, nil
}

func byLocalPath(a, b upstreamRule) int { return strings.Compare(a.LocalPath, b.LocalPath) }

// vendoredRules reads every rule file in the vendored tree, keyed by its slash-separated path under dir.
func vendoredRules(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(p) != ".yml" {
			return err
		}
		content, err := os.ReadFile(p) //nolint:gosec // walking the directory the caller named.
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = content
		return nil
	})
	return out, err
}

// apply brings the vendored tree up to the snapshot: it copies every new and changed rule verbatim and regenerates the manifest.
// A withdrawn rule is left in place, because upstream may have withdrawn it for a reason worth recording before it is removed.
//
// Every file is downloaded and checked against its blob id before anything is written, so a failed or corrupted download leaves
// the tree as it was rather than half-synced.
func apply(ctx context.Context, src upstream, dir string, d diff) error {
	toWrite := append(slices.Clone(d.New), d.Changed...)
	contents := make([][]byte, len(toWrite))
	for i, rule := range toWrite {
		content, err := src.File(ctx, d.Commit, rule.RepoPath)
		if err != nil {
			return fmt.Errorf("download %s: %w", rule.RepoPath, err)
		}
		if got := gitBlobSHA(content); got != rule.BlobSHA {
			return fmt.Errorf("download %s: content has blob id %s, the snapshot says %s", rule.RepoPath, got, rule.BlobSHA)
		}
		contents[i] = content
	}
	for i, rule := range toWrite {
		dst := filepath.Join(dir, filepath.FromSlash(rule.LocalPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(dst, contents[i], 0o644); err != nil { //nolint:gosec // vendored source, committed to the repository.
			return err
		}
	}
	return writeManifest(dir)
}

// writeManifest records the SHA-256 of every rule file in the vendored tree, sorted by path, in the format sha256sum writes.
func writeManifest(dir string) error {
	vendored, err := vendoredRules(dir)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(vendored))
	for p := range vendored {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256(vendored[p]), p)
	}
	return os.WriteFile(filepath.Join(dir, manifestName), []byte(b.String()), 0o644) //nolint:gosec // committed to the repository.
}

// report renders the diff as the Markdown a sync pull request carries.
func report(d diff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Upstream: SigmaHQ/sigma at %s.\n\n", d.Commit)
	if d.empty() {
		b.WriteString("The vendored macOS corpus matches upstream.\n")
		return b.String()
	}
	section := func(title, explain string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", title, explain)
		for _, l := range lines {
			fmt.Fprintf(&b, "- %s\n", l)
		}
		b.WriteString("\n")
	}
	section("New rules", "Copied verbatim. Each imports in monitor mode, or is refused by name if it reads telemetry this sensor does not supply.",
		ruleLines(d.New))
	section("Changed rules", "Copied verbatim; the diff is the review.", ruleLines(d.Changed))
	withdrawn := make([]string, len(d.Withdrawn))
	for i, w := range d.Withdrawn {
		withdrawn[i] = "`" + w.LocalPath + "`: no longer among upstream's rules"
		if w.Deprecated != "" {
			withdrawn[i] += ", moved to `" + w.Deprecated + "`"
		}
	}
	section("Withdrawn upstream", "**Not removed.** Read why upstream withdrew each before deleting it here.", withdrawn)
	return b.String()
}

func ruleLines(rules []upstreamRule) []string {
	lines := make([]string, len(rules))
	for i, r := range rules {
		lines[i] = "`" + r.LocalPath + "` from `" + r.RepoPath + "`"
	}
	return lines
}

// errOutOfDate is returned by a check that found differences, so the command exits non-zero.
var errOutOfDate = errors.New("the vendored macOS corpus differs from upstream")
