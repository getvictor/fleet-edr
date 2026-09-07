# Tell the operator when a host is not taking commands

## Why

The correctness half of issue #711 is done: a wedged control stream is detected (#731), the poll is a bounded floor (#728), and a stranded command can be withdrawn or aged out (#730). What is left is that an operator who issues a command still has no signal, short of reading the command row, that the host never took it.

The incident that motivated it had a `kill_process` pending for 75 minutes against a host reporting `overall_status: healthy` with 49.6M events flowing. Every underlying fault is now fixed, so the failure can no longer be permanent; what remains is the diagnosis cost, which is why this is filed separately (#732) rather than holding the fixes.

## What changes

Host health gains a derived condition when a host has commands that aged out undelivered. It is derived from data already stored, as the issue asked, rather than adding a health writer: the `expired` status added in #730 is the trigger, and the existing derived-component seam already composes server-concluded conditions alongside agent-reported ones. The console renders both from one list, so no console change is needed.

Only expired commands count. A command reaches that status only by waiting out its whole delivery window with no agent claiming it, so each one is direct evidence. Pending commands are deliberately not counted anywhere in this path: a command queued a moment ago against a laptop that is asleep is the ordinary case, and counting it would mark most of a normal fleet as faulty.

Degraded rather than unhealthy, matching the other derived conditions: the expiries are certain, but "the host is at fault" is an inference, and a machine powered off for two days accumulates them with nothing wrong.

## Neither context imports the other

Commands belong to the response context and host health to detection. Rather than add a cross-context edge for two integers per host, both ports are declared where they are consumed and adapted in `cmd/main`, which is the only place that knows both. This is the same inversion the response context already uses in the other direction, where it takes detection's `RecordHostSeen` as its `Heartbeat` closure.

Construction order forces the shape: `cmd/main` builds detection first (response needs its heartbeat), so detection takes its reader through a post-construction setter rather than a `Deps` field.

## It also closes out CountPending

`response/api.Service.CountPending` returned a fleet-wide pending total, was written for an OTel gauge it was never wired to, and could not answer this question anyway, since "is THIS host taking commands" is not recoverable from a total. It is removed rather than wired, and `UndeliverableByHost` takes its place.
