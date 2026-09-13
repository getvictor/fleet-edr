# The server stores the watched-path set and pushes it to hosts

Issue #998 (ADR-0008 step 4). The sensor change taught the extension to watch paths the server pushes on top of its built-in sudoers paths. This change gives the set a home on the server, an API to change it, and the push that carries it to hosts. A later change keeps hosts enrolled after a change converged on it, and another lets an operator edit the set in the console.

## What changes

- **One stored set.** A single row holds the version and the list of paths, replaced whole. Version 0 is the empty set every host already watches.
- **`GET /api/v1/detection-config/watched-paths`** returns the set, the built-in paths every host watches regardless, and the size bound. Gated on `detection_config.read`.
- **`PUT /api/v1/detection-config/watched-paths`** replaces the set with a reason. Gated on `detection_config.write`, the same people who tune detections. The server validates the set, stores it as the next version, queues a `set_watched_paths` command (`{version, epoch, paths}`, the epoch being the set's update time) for every host with an active enrollment, and audits the change with its reason, the previous and new sets, and how many hosts the push reached. The list is required: a request without one is refused rather than read as an empty set, so a misspelled field cannot clear the set.
- **Ordered under the row lock.** The previous set, the next version and the update time are read and written in one locked transaction, with the time from the database and forced past the previous one. Hosts order sets by version or epoch, so a later version must never carry an earlier epoch, and each concurrent change audits the set it actually replaced.
- **Validation is the one gate.** The agent checks only the envelope and the extension applies what it is given, so the server refuses anything it should not watch: more than 32 entries or 8 KiB encoded (the fan-out repeats the payload on every row of a batched insert of up to 256 hosts, which must stay inside a 4 MiB `max_allowed_packet`), a path that is not absolute and clean, longer than 1023 bytes (in its `/private` spelling; `PATH_MAX` counts the NUL), or carrying an ASCII control character (NUL included), a literal ending in `/`, a prefix not ending in `/`, a duplicate (judged through `/private`), and a prefix at the top level of the filesystem. The last is the one that matters for cost: a prefix such as `/Users/` or `/Library/` would put every write under that tree on the wire, which is the firehose ADR-0008 removed. A path under `/private/etc`, `/private/tmp` or `/private/var` is judged by its root-linked form, so the rule cannot be walked around through the firmlink.
- **A push that misses hosts does not fail the change.** The stored set is authoritative once written; the response and the audit row count the hosts that were missed, and say `host_lister_error` when the enrolled hosts could not be listed at all, as application control does.

## Out of scope

- Hosts that enroll, or are offline for longer than a queued command lives, after a change. The next change converges them.
- Scoping the set to host groups. The only host group today is all hosts.
- The console editor.
