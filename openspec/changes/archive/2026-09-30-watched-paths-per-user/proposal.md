## Why

Several macOS persistence and credential techniques that issue #1167 lists as uncovered live in each user's home folder rather than at one system path: SSH `authorized_keys` (MITRE T1098.004), and per-user launch and preference files. The watched-path set only takes absolute paths, and Endpoint Security mutes only literal paths and prefixes, so the only way to watch `~/.ssh/authorized_keys` was to list every account's home by hand and keep the list current as accounts come and go. A prefix at `/Users/` would watch everything and is refused.

## What changes

- A watched path may start with `~/` to name the same path in every user's home folder. The server validates it as the path it would be in a home at the root, so a prefix needs two components below the home, as an absolute prefix needs two below the root.
- Each host's security extension expands such an entry into one path per home: root's and each account with a user ID of 500 or above, read from the directory service. It re-reads the accounts every five minutes and re-applies the set when they change, so an account added later is watched without a push.
- The watched-path editor and the operations guide say how to name a path in every home.

## Not changed

Absolute paths, the set's limits, and the push, ordering and persistence of the set are unchanged. An extension from before this change skips a `~/` entry, as it skips any entry it cannot apply, and watches the rest of the set. No rule reads these paths yet; rules for the techniques follow as their own changes.
