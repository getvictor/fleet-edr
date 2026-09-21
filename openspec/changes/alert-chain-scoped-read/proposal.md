# An alert's chain can be read on its own

Issue #1138, items 1 and 2. #1139 made the alert's chain always present in the page; this stops the page being the host's day.

The alert view asks for the host's process forest over a 24-hour window and filters to the chain in the client. That costs rows in proportion to how busy the host is, pays for a count of everything the window matched, and shows a truncation notice about rows the analyst never wanted. On a host with 26,441 processes in the window, the analyst wanted seven of them.

## What changes

- **`GET /api/hosts/{id}/tree?scope=chain&pin=<id>` reads the chain**: the named process, its ancestors, and its descendants. Nothing else.
- **No count runs for it.** The count exists to say how much of the host's window was left out, and a chain read left none of it out because it never read the window. That is issue item 2, and it falls out of item 1 rather than needing its own mechanism.
- **The page asks for it while focused on the alert chain**, and for the window when the analyst switches to the full tree. The toggle already meant that; now the read follows it.

## How a descendant is decided

A process's children are the rows naming its process number as their parent AND forked within its lifetime. The lifetime bound is what keeps a recycled number out: a number is reused only after its holder exits, so a row forked after this process exited belongs to whatever took the number next. Without it an analyst would be shown activity the alerted process never spawned, attributed to it.

Descendants are the only unbounded direction, so they carry a cap; ancestors are bounded by the depth of a process tree. A chain read reports `truncated` only about that cap.

## What this does not do

`scope=chain` is opt-in. The host page, and the alert view's own full-tree toggle, still read the window, still count, and still show the notice, because for those the notice is describing something real.

## Out of scope

The default alert window, which now matters only to the full-tree toggle and to the descendant bound.
