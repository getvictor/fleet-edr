# The extension watches file paths the server pushes

Issue #998, first of three changes (ADR-0008 step 4). This one makes the sensor able to take a watched-path set. The second stores the set on the server and pushes it to hosts; the third lets an operator edit it in the console.

## Why

The file-tamper client observes only paths compiled into the extension: `/etc/sudoers` and `/etc/sudoers.d/`. Watching anything else, whether a ransomware canary, a credential store, an operator's integrity-monitored directory, or the paths two refused SigmaHQ rules need (`/etc/emond.d/rules/` and `/Library/StartupItems/`), means shipping a new extension and waiting for it to roll out.

The obvious fix is the wrong one, and ADR-0008 records why: broad `NOTIFY_OPEN` and `NOTIFY_CREATE` on the primary client built a queue backlog that delayed detection by about 12 minutes. What replaced it works. The file-tamper client unmutes all target paths, mutes the ones it wants, and inverts target-path muting, so its cost scales with the watched set rather than with system activity. Only the set itself needs to stop being fixed.

## What changes

- **The watched set is the built-in paths plus a pushed set.** The built-in sudoers paths stay watched whatever is pushed, because the shipped sudoers rules depend on them. A pushed set only adds paths, so the default, an empty pushed set, is exactly today's behaviour.
- **A pushed set is applied to the running client, without a restart.** The client mutes the paths the new set adds and then unmutes the ones it drops. A path in both sets is never touched, so replacing the set opens no gap in what was already covered.
- **A pushed set survives a restart.** The extension persists a set beside the application-control snapshot before applying it, and starts from it, so a restarted extension watches the operator's paths from its first event. A set it cannot write is not applied, so the running and persisted sets never differ.
- **Newest set wins.** Commands can reach a host out of order (a poll returns pending commands newest first, and the poll and the control stream can overlap), so the extension applies a set only when its version or its epoch, the server's update time, is ahead of the last one it accepted. Epoch is what still orders sets after a server database restore sends versions backwards, as `policy_epoch` does for application control.
- **Forward-compatible entries.** An entry is a path and a match type, `literal` or `prefix`. An entry the extension does not understand is skipped and counted, and the rest are applied; a payload that is not a watched-path document at all leaves the set unchanged.
- **No firehose, even from a bad push.** The extension applies every rule the server applies to an entry again, because what reaches the kernel is a C string: a path with a NUL or `..` segment can read as deep while muting a top-level one. So a prefix at the top of the filesystem (`/`, `/Users/`, `/etc/` through `/private`), however spelled, is skipped by the extension itself, not only refused by the server.
- **Transport.** A new `watched_paths.update` XPC message carries the set from agent to extension, and a new `set_watched_paths` command (`{version, epoch, paths}`) carries it from server to agent. The agent validates the envelope (a positive `version`, a `paths` array) and forwards the raw bytes, as it does for `set_application_control`.
- A pushed path that fails to mute is logged, and the running client then unmutes nothing that update drops; the next update tries the path again. After a restart the client watches the persisted set (#1018 tracks whether it should reconstruct the retained paths). A built-in path that fails stays fatal, as it was, because after inversion it would silently go unobserved.

## Out of scope

- Storing the set on the server, bounding its size, and pushing it to hosts (the second change), and editing it in the console (the third).
- Making the two refused `file_event` SigmaHQ rules loadable. That needs the rule loader to know what a host watches.
- Re-subscribing to broad `NOTIFY_OPEN`, per ADR-0008.
