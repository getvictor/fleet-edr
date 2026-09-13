// Command sigma-sync compares the vendored SigmaHQ macOS corpus with upstream, and with -apply brings it up to date (issue #1003).
//
// The vendored tree's manifest test catches local drift: an edit, addition or deletion made here. Nothing offline can catch upstream
// drift, a rule fixed or withdrawn by SigmaHQ, which is why this is a command that reaches the network rather than a unit test,
// the same shape as `task attack:latest-check`.
//
// Usage:
//
//	go run ./tools/sigma-sync              # report differences; exits non-zero when there are any
//	go run ./tools/sigma-sync -apply       # copy new, changed and moved rules verbatim and regenerate the manifest
//
// A rule upstream moved to another category is written at its new path, and -apply removes the old vendored copy first, because the
// loader refuses two files with one rule id. -apply never deletes a vendored rule upstream has withdrawn, and never touches the
// pinned import and refusal counts in TestLoadImported_TheWholeUpstreamCorpus: a new rule is meant to fail that test until a person
// reads it and updates the numbers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

// syncTimeout bounds the whole run, so a scheduled job cannot hang on a slow network.
const syncTimeout = 5 * time.Minute

func main() {
	dir := flag.String("dir", "server/rules/internal/catalog/imported", "the vendored corpus")
	repo := flag.String("repo", "SigmaHQ/sigma", "the upstream repository")
	ref := flag.String("ref", "master", "the upstream branch or commit to compare with")
	applyChanges := flag.Bool("apply", false,
		"copy new and changed rules, move recategorised ones (removing the old copy), and regenerate the manifest")
	reportPath := flag.String("report", "", "also write the Markdown report to this file")
	flag.Parse()

	// The command's wiring site: main reads the token so the source takes it as a value.
	token := os.Getenv("GITHUB_TOKEN") //nolint:forbidigo // wiring site, see above
	if token == "" {
		token = os.Getenv("GH_TOKEN") //nolint:forbidigo // wiring site, see above
	}
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	err := run(ctx, newGitHub(*repo, *ref, token), *dir, *applyChanges, *reportPath)
	cancel()
	if errors.Is(err, errOutOfDate) {
		log.Print(err)
		os.Exit(3)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// run compares, optionally applies, and prints the report. Without apply, a difference is errOutOfDate.
func run(ctx context.Context, src upstream, dir string, applyChanges bool, reportPath string) error {
	commit, entries, err := src.Snapshot(ctx)
	if err != nil {
		return err
	}
	d, err := compare(dir, commit, entries)
	if err != nil {
		return err
	}
	text := report(d)
	fmt.Print(text)
	if reportPath != "" {
		if err := os.WriteFile(reportPath, []byte(text), 0o600); err != nil {
			return err
		}
	}
	switch {
	case d.empty():
		return nil
	case applyChanges:
		return apply(ctx, src, dir, d)
	default:
		return errOutOfDate
	}
}
