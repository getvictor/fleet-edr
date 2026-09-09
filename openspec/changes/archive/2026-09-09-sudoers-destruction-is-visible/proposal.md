# Destroying sudo policy is visible

## Why

`: > /etc/sudoers` empties the file and produces **no telemetry at all**. Deleting a live fragment is equally invisible. Both destroy sudo policy, and until now the endpoint reported neither.

Measured on edr-dev (macOS 26.3), one probe run per scenario on a freshly seeded 37-byte file, with sizes proving the action happened:

| action | size | events |
| --- | --- | --- |
| `bash -c ': > file'` | 37 → 0 | **0** |
| `sh -c ': > file'` | 37 → 0 | **0** |
| `python3 open(f,'w')` | 37 → 0 | **0** |
| `truncate -s 0 file` | 37 → 0 | 1 (`TRUNCATE`) |

`#934` proposed `NOTIFY_TRUNCATE` as the fix and it is not sufficient: it covers `truncate(2)` and `ftruncate(2)` only. `open(O_TRUNC)`, which is what every shell redirect and most language runtimes use, is a different kernel path that emits nothing across CREATE, WRITE, TRUNCATE, RENAME or UNLINK.

## What changes

Collection gains three subscriptions, all confirmed deliverable under the existing inverted target-path muting:

- `NOTIFY_OPEN`, filtered **in the extension** to opens carrying `O_TRUNC`. This is what makes the shell redirect visible, and the filter is what keeps it affordable: `sudo` opens `/etc/sudoers` on every invocation, so an unfiltered subscription would report routine privilege checks as file activity.
- `NOTIFY_TRUNCATE`, for the `truncate(2)` half.
- `NOTIFY_UNLINK`, for deletion.

Detection gains `sudoers_destroyed`, a rule of its own rather than an extension of `sudoers_tamper`. The reason is the ATT&CK mapping rather than tidiness: `sudoers_tamper` is T1548.003, Abuse Elevation Control Mechanism, which is about GAINING elevated execution. Emptying or deleting a sudoers file grants nothing. Reporting destruction under the escalation technique would put it on a coverage page under a heading that misdescribes it.

The new rule maps to T1070.004 (Indicator Removal: File Deletion), for an attacker removing the grant they added, and T1531 (Account Access Removal), for emptying `/etc/sudoers` and revoking every administrator at once. The rule cannot tell those apart and both are worth naming.

## The narrowing is load-bearing here, not merely tidy

The rule matches only names sudo will parse, the same pattern `sudoers_tamper` uses. That is not carried over for consistency: `visudo` UNLINKS its own `<name>.tmp` on every run, measured on edr-dev, so a rule matching any direct child would report every legitimate sudoers edit as a policy deletion. It is the same over-match that made `sudoers_tamper` fire on visudo (#933), arriving through the deletion door.

## Impact

- Affected specs: `endpoint-event-collection`, `server-detection-rules-engine`
- Affected code: `extension/edr/extension/FileTamperSubscriber.swift`, `EventSerializer.swift`, `schema/events.json`, `server/rules/internal/{sigmabind,export,catalog}`
- Closes #934
