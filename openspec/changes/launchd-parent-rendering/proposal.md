# Name pid 1 as a shell's parent so the class can be suppressed

## Why

A shell started directly by `launchd` has no parent process ROW, so `lookupParentOf` returns nothing and the alert named its parent `(unknown)`. Those alerts fire deliberately: the absence is real rather than a gap in the recorded tree, and issue #830 narrowed the ancestry-incomplete drop specifically so this class would keep counting.

But they inherited the problem #829 set out to remove. Parent exclusions match on a path, `(unknown)` matches nothing, and `parentExcluded` returned false before consulting any resolver at all because every match type needs a process row to read. An operator seeing one of these repeatedly had no way to silence it short of disabling the whole rule, which loses every detection the rule makes rather than the one they asked about.

## What changes

The parent of a shell whose PPID is 1 is named `/sbin/launchd`, which is what pid 1 IS on macOS rather than a synthetic stand-in for a missing record, and the path-glob exclusion is consulted for it. A claimed PPID of 0 is the kernel, not launchd, and continues to report that the parent cannot be named: rendering it as launchd would state something false and would let a launchd exclusion silence a chain that was never launchd's.

Both `suspicious_exec` and `shell_network_connect` are affected, since they share the ancestor walk and the rendering.

## Decision recorded

The issue offered a second option: give the exclusion resolver an explicit way to match "no parent" rather than a path standing in for an absence, described there as more honest and more work. The recorded reason for choosing the rendering instead is that the two suppress exactly the same set of alerts, so the breadth risk the issue attaches to the path glob is identical either way, and the distinction is one an operator never observes. Where the choice does differ is that a path is a thing an operator can already write, read back, and reason about with the exclusion types the surface has today.

The breadth itself is real and is stated rather than designed away: an exclusion for `/sbin/launchd` silences every launchd-started shell chain for that rule, which includes real persistence execution. That is recorded in both rules' limitations, so an operator reads it where they would write the exclusion.

## Not doing

Signature exclusions still require a process row, so a launchd parent is not suppressible by team ID, signing ID, or cdhash. Pid 1's own signing identity is not read, because that would report an identity for a row the finding does not have and would break the existing requirement that a finding with no resolved parent is not suppressed by a signature exclusion.
