# Health components share one shape

## Why

The host header's Details popover lists each capture provider as its own component: a status badge, the component's name, a message, and how long it has been in that state. Four components rendered in two different shapes at the same width.

The row was a single wrapping flex line, so where the message landed depended on how long the component's NAME was. "DNS proxy" is short enough that its message fitted beside it; the three longer names pushed theirs onto the next line. An operator scanning four providers for the one that is broken read three rows in one shape and one in another, for no reason connected to the health being reported.

It is an incidental wrap rather than a responsive one: the popover is fixed-width, so the shape is stable per component and simply differs between them.

## What changes

The component's badge and name always occupy the first line, and its message and age always occupy the second. Neither the message nor the age is rendered when absent, so a component with nothing to add leaves no empty line.

No change to what is reported, only to how consistently it is laid out.

## Impact

`ui/src/components/HostHeader.tsx`, `ui/src/components/HostHeader.scss`. Found by a browser pass over the v0.5 UI surfaces; no layer below the browser lays the panel out, so nothing else could have seen it.
