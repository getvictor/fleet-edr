# Wrap long exclusion values within a capped Value column

Issue #1032.

## The problem

The detection tuning page lists exclusions in a table whose Value column holds a path, glob, team ID or hash. A path or glob has no spaces, so the browser has no place to break it, and a long one sets the whole table's width. On a live deployment the value `/Users/<user>/.local/share/mise/installs/lefthook/*/lefthook_*_MacOS_arm64` pushes the Reason, Expires and Created by columns out of view at an ordinary window width.

The exclusion guidance steers operators toward full absolute paths rather than short leading-wildcard fragments, so long values are the expected case, not an edge.

## What changes

- **The Value column has a maximum width.** A value is laid out as wide as it is up to 24rem, and the column adds the table's usual cell padding. A longer value wraps onto further lines inside the column rather than widening the table.
- **The cap applies to the value, not the table cell.** A table cell ignores `max-width` in automatic layout, and letting the cell break anywhere shrinks the column far below the cap, wrapping a long glob over many lines while the table has room to spare. Capping the value block keeps the column at the cap and wraps only what exceeds it.

## Why this approach

Truncating with an ellipsis was the alternative. It hides the part of a glob an operator most needs to read, the suffix that says which binary is trusted, and makes the value unreadable without a tooltip that keyboard and touch users do not reliably get.
