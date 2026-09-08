# sudoers_tamper sees the atomic replace, and stops alerting on files sudo ignores

## Why

Two defects, and they have to be fixed together because either one alone makes things worse.

**The evasion.** Writing a temp file and renaming it onto a sudoers path is invisible to `sudoers_tamper` when the source is outside the watched set. `mv /tmp/x /etc/sudoers.d/evil` produces no CREATE and no WRITE on a watched path, so the rule never sees the escalation. ADR-0008 decision point 3 already includes `RENAME`; the subscription was never added, on the grounds that watching rename would fire on every legitimate `visudo` edit.

**That objection does not hold, and the reason it does not is itself a bug (#933).** Measured on edr-dev: one `visudo -f /etc/sudoers.d/<name>` produces CREATE, WRITE and UNLINK on `<name>.tmp`, a sibling inside the watched `/etc/sudoers.d/` prefix. The rule's path pattern treats `<name>.tmp` as a direct child, so it fires. The visudo noise the objection warns about already exists, without any rename subscription. What rename adds is not noise; it is the only event carrying a source path, which is what lets the two be told apart at all.

**And the files it fires on cannot grant anything.** `sudoers(5)` says sudo skips names in `sudoers.d` that contain a `.` or end in `~`. Verified with three files of identical content differing only in name: `zzdotless` loads, `zz.dotted` and `zztilde~` are ignored. So today the rule raises a Critical privilege-escalation alert on a file sudo will never parse.

**Why they cannot be split.** Narrowing the path pattern to loadable names (the #933 fix) removes a detection that currently works by accident: `printf ... > /etc/sudoers.d/evil.tmp; mv evil.tmp evil` is caught today by the CREATE/WRITE on the `.tmp`. Narrow without subscribing rename and that attack goes silent. Subscribe rename without narrowing and the false positive stays. Shipping both together is the only ordering that is not a regression in one direction or the other.

## What changes

Collection gains the one event that makes the escalation observable, confirmed deliverable under the existing inverted target-path muting: `NOTIFY_RENAME`, carrying **both** paths. Muting matches on either side, so a rename into, within, or out of the watched set is delivered.

It ships as its own event type rather than as a field bolted onto `open`, because Sigma already has the shape: the `file_rename` category carries `SourceFilename` and `TargetFilename`. Reusing it keeps every field the rule reads inside Sigma's own taxonomy, rather than inventing one only we supply, and it stops `open` from accumulating another meaning it does not have.

This supersedes a claim in the pending `retire-vestigial-open-flag-fields` change, which recorded that `sudoers_tamper` had become plain Sigma (`portable: standard`). That was true when it was written and is not after this change; both folders archive together, so the resolution is recorded here rather than by rewriting what that change did.

The combined rule is nonetheless exported as `portable: mapped`, and that is a separate limitation worth stating plainly: Sigma permits one logsource category per rule, so a rule reading both `open` and `file_rename` cannot be routed correctly by an external engine whatever its fields. Review caught this claim being made the other way round. The exporter now derives it, so the file says which category another engine would not route rather than promising coverage it cannot deliver.

Detection changes from "a write touched a sudoers path" to "a file sudo will load was created or changed":

- The path pattern narrows to names sudo actually loads, so `<name>.tmp` no longer fires. That is #933.
- A rename fires when its **destination** is a name sudo will load, which is the instant a file becomes live policy, whatever it was called before.

Truncation and deletion are **not** in this change. They are denial of the policy rather than escalation, the fix needs `NOTIFY_OPEN` rather than the `NOTIFY_TRUNCATE` the issue assumes, and together they would put this well past a reviewable size. Split to #934, which depends on the wire shape introduced here.

## The measurement behind the design

Every claim above is from a standalone ESF probe on edr-dev (macOS 26.3) using `FileTamperSubscriber`'s exact muting setup, not from documentation.

Rename is delivered, and matches on either path:

| action | delivered | paths |
| --- | --- | --- |
| `mv /tmp/zz-evil /etc/sudoers.d/zz-evil` | yes | `src=/private/tmp/zz-evil dst=/private/etc/sudoers.d/zz-evil` |
| `mv /etc/sudoers.d/zz-probe.tmp /etc/sudoers.d/zz-probe` | yes | both inside the watched prefix |
| `mv /etc/sudoers.d/zz-probe /tmp/zz-out` | yes | `src` inside, `dst` outside |

sudo ignores names it will not parse, which is what makes the narrowed pattern correct rather than merely quieter. Three files, identical content, only the name differing, each checked with `sudo -l`:

| file | loaded |
| --- | --- |
| `/etc/sudoers.d/zzdotless` | yes |
| `/etc/sudoers.d/zz.dotted` | no |
| `/etc/sudoers.d/zztilde~` | no |

And one `visudo -f /etc/sudoers.d/zz-visudo` produces `CREATE`, `WRITE` and `UNLINK` on `zz-visudo.tmp`, a sibling inside the watched prefix, which the current pattern matches. That is the false positive, and it is why the objection to subscribing rename does not hold.

### One thing not verified

`visudo`'s commit rename was not observed. macOS ships `env_editor` off, so `visudo` ignores `EDITOR`, runs its built-in editor, reports `unchanged`, and never commits; setting `Defaults env_editor` did not change that across three attempts. The `CREATE` / `WRITE` / `UNLINK` sequence is consistent with a commit that renames, and #917's own quoted output shows the same `unchanged` line, so that claim is inferred there too. It does not change this design, because the rule keys on whether the destination is loadable rather than on which temp-file convention an editor uses, but it is recorded rather than assumed.

## Impact

- Affected specs: `endpoint-event-collection`, `server-detection-rules-engine`
- Affected code: `extension/edr/extension/FileTamperSubscriber.swift`, `extension/edr/extension/EventSerializer.swift`, `schema/events.json`, `server/rules/internal/catalog/sudoers_tamper.go` and its rule pack
- Closes #917 and #933; #934 depends on the wire shape added here
