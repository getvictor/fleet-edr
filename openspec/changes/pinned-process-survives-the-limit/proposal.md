# A pinned process is in the page it was pinned into

Issue #1138. The process-tree read is `ORDER BY fork_time_ns DESC LIMIT`, so it returns the newest rows in the window. The alert view asks for a 24-hour window around the alert and pins the alerted process, but pinning only stops sibling aggregation folding that process; it does not get it fetched. On a busy host everything forked after the alert fills the page first, so the page the alert view asked for could not contain the alert it was opened for.

Measured on one host: 10,321 processes forked after an alert inside that alert's own window, putting the alerted process about 10,000 rows past the limit. The page then showed the whole host, and the analyst was looking at unrelated activity under a "Showing 2,000 of more than 10,000" notice.

## What changes

- **The pinned process is in the result whatever the limit admitted**, read by its id when the window read did not cover it.
- **Its ancestors come with it.** `buildForest` links ppid to pid within the fetched rows only, so a process whose parent missed the page becomes a root. Returning the pinned row alone would place the alerted process in the tree as an orphan, which is a different wrong answer rather than the right one.
- **The page's own counts are unchanged.** `returned` keeps describing what the limit admitted, so the "showing N of M" notice goes on describing the window read rather than quietly gaining rows the read never admitted.

## Why the ancestors are walked one level at a time

Each parent is resolved with the store's existing `GetProcessByPID`, which is the one lookup that answers "which generation of this pid was running at that instant". Its ordering is the product of issues #714, #723, #724 and #799, and its own comment warns that a second copy of it would drift. A recursive CTE joining on `ppid` would be that second copy, and it could not express the ordering anyway: MySQL cannot apply `ORDER BY ... LIMIT 1` per row inside a recursive member. One query per level, bounded by the depth of a process tree rather than by how busy the host is, is the cheaper correctness.

## What this does not do

The read stays host-wide and window-bounded, so a busy host still pays for a page of rows it mostly does not need, and still shows the truncation notice. Scoping the read to the chain, which removes both, is the follow-up this issue's first item describes.

## Out of scope

The default alert window, and ordering the window read around the anchor rather than newest-first. Both are mitigations for a read that should not be host-wide at all.
