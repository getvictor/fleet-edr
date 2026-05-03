# Schedule audit log

Append one line per scheduled-task run, even when there are no findings. Format:

```
YYYY-MM-DD  <task-name>  <result>  [PR #N | issue #N | no findings]  [notes]
```

`<result>` is one of `done`, `partial`, `skipped`. `partial` means time budget hit before the task was complete; the next run
should pick up where this one left off.

The log is the audit trail proving the cadence is being honoured. An empty log over a quarter is the signal to drop the schedule
or change the cadence - running tasks with no record is the same as not running them.

---

<!-- entries below, newest at the bottom -->
