# Say where retained process records begin

## Why

The process graph and the event timeline are kept on separate windows (issue #1153). Completed process records are deleted after `EDR_RETENTION_DAYS`, except those an alert references; events expire from ClickHouse on their own 30-day window. On an alert older than the process window, the graph shows the alerted process alone while the timeline beside it is complete. The read is not truncated, so nothing on the page says why, and the graph reads as broken. On dogfood that was most of the alert list, because the quickstart set the process window to 7 days.

## What changes

- The process-tree response reports `retained_from_ns`, the moment before which completed process records have been deleted, and omits it when retention is disabled.
- The graph says so when its window starts before that moment: earlier processes are missing unless an alert references them, and the timeline may still show them.
- The quickstart's default process retention goes from 7 days to 30, the server's own default and the event window. The 7-day value was justified by events being the dominant MySQL store, which stopped being true when events moved to ClickHouse.

## Not changed

What retention deletes, and the server's default, are unchanged. Rebuilding pruned process records on demand from the retained events is not attempted: the graph builder is stateful, so a replay is not a pure function of a window.
