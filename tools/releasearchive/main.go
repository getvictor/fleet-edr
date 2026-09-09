// releasearchive drives the batched OpenSpec archive at a release boundary, which `task release:archive` invokes.
//
// It exists because the ORDER is the hazard. `openspec archive` applies a `## MODIFIED Requirements` entry by replacing the
// canonical requirement whole, so when one pending change adds a requirement and another modifies or retires it, applying the
// pair the wrong way round discards the later text with no error at all: `openspec validate --strict` passes on a truncated
// requirement and `spectrace check --strict` passes as long as the surviving scenarios still carry markers. Commit f7690a49
// archived seven folders in one pass, four of them touching web-ui and four touching endpoint-event-collection, and 197 of the
// 212 findings issue #905 tracks come from that one commit.
//
// `spectrace archive-order` already computes a safe order. What it could not do was apply one, and a checklist step telling a
// release engineer to read an order and retype it in sequence is an instruction rather than a gate. This closes that: the order
// comes from the tool, and nothing is archived when the tool cannot produce one.
//
// It does NOT verify the archive was lossless. That is the separate before/after `spectrace archive-verify` comparison in the
// release checklist, and this program removes the ordering decision from the human rather than replacing that check.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// noSafeOrderExit is the exit status `spectrace archive-order` uses for a dependency cycle, which is a human decision (split one
// of the changes, or reconcile the requirements they contend over) rather than something to retry. Every other non-zero status is
// a tool or IO failure. Both stop the run, and the two are separated only so the operator is sent to the right one.
const noSafeOrderExit = 1

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "release:archive: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("release-archive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "print the sequence and stop; archive nothing")
	root := fs.String("root", ".", "repository root; both tools run there")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bin, cleanup, err := buildSpectrace(ctx, *root, stderr)
	if err != nil {
		return err
	}
	defer cleanup()
	return archiveAll(ctx, execCommands{root: *root, spectrace: bin, stdout: stdout, stderr: stderr}, *dryRun, stdout)
}

// buildSpectrace compiles the ordering tool to a temporary path and returns it, with the cleanup for the directory it sits in.
//
// Built rather than `go run`, which is how the rest of the Taskfile reaches spectrace, because `go run` exits 1 when the BUILD
// fails and 1 is also how archive-order reports that no safe order exists. Nothing downstream can tell those apart, so a
// compile error would reach the release engineer as "split one of these changes or reconcile the requirements they contend
// over": a wrong instruction rather than a missing one. Building separately keeps a build failure reported as one, and leaves
// exit 1 from the binary meaning only what the checklist says it means.
func buildSpectrace(ctx context.Context, root string, stderr io.Writer) (bin string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "release-archive")
	if err != nil {
		return "", nil, fmt.Errorf("build spectrace: %w", err)
	}
	bin = filepath.Join(dir, "spectrace")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./tools/spectrace") //nolint:gosec // bin is a path this program made
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("build spectrace: %w", err)
	}
	return bin, func() { os.RemoveAll(dir) }, nil
}

// commands is the seam between the sequencing this program owns and the two external tools it drives. The tests substitute it to
// drive a failure partway down the list, which is not something a real archive run can be asked for on demand.
type commands interface {
	// order returns the pending changes in the order the archive must apply them. Any error is a hard stop: an order that could
	// not be computed is not an invitation to fall back on alphabetical, which is the bug.
	order(ctx context.Context) ([]string, error)
	// archive applies one change, merging its delta into the canonical specs and moving the folder under changes/archive/.
	archive(ctx context.Context, change string) error
}

// archiveAll prints the sequence, then applies it.
//
// The plan is printed before the first archive runs because a release engineer watching this has one chance to stop it: after the
// first `openspec archive` the working tree has moved and the only way back is git.
func archiveAll(ctx context.Context, c commands, dryRun bool, out io.Writer) error {
	changes, err := c.order(ctx)
	if err != nil {
		return fmt.Errorf("%w; nothing was archived", err)
	}
	if len(changes) == 0 {
		fmt.Fprintln(out, "release:archive: no pending changes, nothing to archive")
		return nil
	}
	fmt.Fprintf(out, "release:archive: %d pending change(s), to be archived in this order:\n", len(changes))
	for i, change := range changes {
		fmt.Fprintf(out, "  %3d. %s\n", i+1, change)
	}
	if dryRun {
		fmt.Fprintln(out, "release:archive: dry run, nothing archived")
		return nil
	}
	for i, change := range changes {
		fmt.Fprintf(out, "release:archive: [%d/%d] openspec archive %s -y\n", i+1, len(changes), change)
		if err := c.archive(ctx, change); err != nil {
			// Stopping leaves the tree half-archived, which is recoverable by git and by re-running this once the failure is
			// fixed. Carrying on past a failure is not: the changes after it may be the ones that had to follow the one that
			// did not land, and applying them anyway is the loss this exists to prevent.
			return fmt.Errorf("archiving %s failed after %d of %d: %w", change, i, len(changes), err)
		}
	}
	fmt.Fprintf(out, "release:archive: archived %d change(s)\n", len(changes))
	return nil
}

// execCommands drives the two real tools.
type execCommands struct {
	// root is the repository root. Both tools run there: `openspec archive` resolves openspec/ from the working directory, and
	// the ordering pass has to read the same tree the archive is about to mutate.
	root string
	// spectrace is the ordering tool's path. run builds it to a temporary one; the tests reuse that build and point root at a
	// fixture tree rather than at the repository's own pending changes.
	spectrace      string
	stdout, stderr io.Writer
}

// order takes the sequence from `spectrace archive-order --porcelain`, whose stdout is one change name per line.
//
// --porcelain rather than a parse of the human report: the report is prose written for a release engineer, and a parser for it
// would be one edit to that prose away from silently reordering a release. The reasons behind the order still reach the
// operator, because --porcelain writes the constraints to stderr and this passes stderr straight through.
func (c execCommands) order(ctx context.Context) ([]string, error) {
	cmd := c.orderCmd(ctx)
	out, err := cmd.Output()
	if err != nil {
		return nil, orderFailure(err)
	}
	return parseOrder(out), nil
}

// orderCmd builds the ordering invocation. Separate from running it so a test can pin the argv, which is where --porcelain and
// the absence of any fallback flag live.
func (c execCommands) orderCmd(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.spectrace, "archive-order", "--porcelain") //nolint:gosec // the path is one this program built
	cmd.Dir = c.root
	cmd.Stderr = c.stderr
	return cmd
}

// orderFailure says which of the two hard stops this is. Both refuse to archive; they differ in what the operator does next.
func orderFailure(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == noSafeOrderExit {
		return errors.New("spectrace archive-order found no safe order: the report above names the changes that each have to " +
			"precede another, so split one of them or reconcile the requirements they contend over")
	}
	return fmt.Errorf("spectrace archive-order failed: %w", err)
}

// parseOrder reads the porcelain list. Trimming and skipping blanks rather than trusting the exact byte count keeps this working
// if the tool ever ends without a final newline; the names themselves are directory names and pass through untouched.
func parseOrder(out []byte) []string {
	var changes []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if change := strings.TrimSpace(line); change != "" {
			changes = append(changes, change)
		}
	}
	return changes
}

// archive applies one change, with openspec's own output passed through so a failure is diagnosable from the task's log.
//
// Never --skip-specs. That flag skips the merge into openspec/specs/**, which is the entire purpose of the release archive;
// CLAUDE.md reserves it for a change that shipped no delta at all, and that is a human's call on one named change rather than a
// default for a batch.
func (c execCommands) archive(ctx context.Context, change string) error {
	return c.archiveCmd(ctx, change).Run()
}

// archiveCmd builds one archive invocation. Separate from running it so a test can pin the argv, which is the only place the
// --skip-specs that must never appear could appear.
func (c execCommands) archiveCmd(ctx context.Context, change string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "openspec", "archive", change, "-y") //nolint:gosec // change is a directory name from spectrace
	cmd.Dir = c.root
	cmd.Stdout = c.stdout
	cmd.Stderr = c.stderr
	return cmd
}
