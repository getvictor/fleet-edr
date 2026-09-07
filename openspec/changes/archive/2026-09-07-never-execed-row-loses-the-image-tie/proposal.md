# A record that never executed does not win the image tie

## Why

The image-at-time ordering ends with a bare `exec_time_ns ASC`, and MySQL sorts NULL first under ASC. So a record that never exec'd outranks one whose exec landed at the same instant as the other's fork, and the answer is the pre-exec image for an instant at which the process had executed.

The sharper half is that the batch overlay has no counterpart to that key: it compares the image start, ties, and falls through to the kernel generation. In exactly this case the stored query and the overlay disagree, so the answer depends on whether the record happened to be preloaded into the batch. The batch tests call that the worst shape of bug in this area, because it reproduces only at a batch boundary.

## What changes

- The key is scoped to the records it was written for, the ones whose image had NOT been applied by the instant. It exists to take a re-exec chain's earliest image when a child's stamp fell inside its parent's own fork-to-exec window, and every record in that group has an exec, so the key decides nothing there by being unscoped. All it did unscoped was reverse the applied case.
- Applied records now tie on that key and fall through to the kernel generation, which is exactly what the overlay already does. Neither implementation changes its answer for any other shape.

The overlay is unchanged: it was already right, and the stored query is what moves to meet it.

## Impact

- Affected specs: `server-process-graph-builder`
- Affected code: `server/detection/internal/mysql/processes.go`
