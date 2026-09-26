# Monitor records reachable from the rule, not only from detection tuning

## Why

Monitor records are gated on `alert.read` and their only entry point is the Observed column of the detection-tuning view, which is gated on `detection_config.read`. The analyst role grants the first and not the second, so the records are permitted and unreachable for the role whose job is reading them (issue #1165).

That is most of what the engine observes: 66 imported rules default to monitor, and on the dogfood deployment 1,296 of 2,419 rows in the alerts table are monitor records.

The rule detail page makes it worse rather than neutral. It is gated on `alert.read`, it tells the reader the rule runs in monitor mode, and the only thing it offers them is a link into detection tuning, which will refuse them.

## What changes

The rule detail page offers a monitor-mode rule's records, and stops linking an operator to detection tuning when they cannot open it.

This is navigation only. The permission model is unchanged: both the page and the records route were already gated on `alert.read`, and nothing here widens what anyone may read.

## Requirement title kept deliberately

The requirement is now about two entry points while its title still names one. The title is kept because it is the marker slug for five test references, and renaming a requirement in OpenSpec is a remove-plus-add whose scenario handling is the known hazard in `openspec_archive_hazards`. Widening the text is the lower-risk change; the title can be corrected in a dedicated pass that moves the markers with it.
