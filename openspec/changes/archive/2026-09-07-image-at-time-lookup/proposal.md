# The process lookup answers with the image that was running

Fixes #799.

## The defect

`GetProcessByPID(hostID, pid, atTimeNs)` brackets on `fork_time_ns <= atTimeNs` and orders by `fork_time_ns DESC, id DESC`. A re-exec preserves the original fork time on every generation of a pid, so every generation of one pid shares that value and `id DESC` decides: the lookup returns whichever generation was written LAST, not the one that was running at the instant asked about.

Concretely, a parent forks a child at T1 and re-executes into a different binary at T2. A rule asking what the parent's image was when it forked the child, with `atTimeNs = T1`, is handed the T2 image. A binary that had not run yet.

## Why it matters

This is the lookup every parent-image and attribution question goes through: `shell_from_office` via `ParentImage`, `suspicious_exec.lookupParentOf`, and the eleven corpus rules #764 imported that read `ParentImage`.

The cost is both halves of a detection. Attribution names a binary that was not involved, and a malicious parent that re-executed into something benign before the batch was evaluated reads as benign, so the detection is missed rather than merely mislabelled.

## Fix

Bracket and order on `COALESCE(exec_time_ns, fork_time_ns)`, the instant the row's own image started running. `exec_time_ns` is the image-replacement instant, and the fallback covers a generation that forked and has not executed, whose only start instant is its fork.

`GetProcessByPIDVersion` already resolves generations this way and its comment sets out the same reasoning, so this brings the two lookups into agreement rather than inventing an approach.

The equality predicates are unchanged, so the index prefix that serves this lookup still applies; the comparison moves from an indexed column to a computed one, which filters the handful of generations a single `(host_id, pid)` has rather than seeking.

## Not in this change

Issue #723 fixed the aliveness half of this bracket (a generation that had exited being returned as live). This is the generation-selection half, and the two together are what "the process at time T" has to mean.
