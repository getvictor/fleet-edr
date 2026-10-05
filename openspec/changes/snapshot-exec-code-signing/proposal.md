## Why

The startup snapshot emitted processes that predate the extension with no code signature (`ProcessSnapshotEnumerator` passed `codeSigning: nil`). The server then held no signature for every process started at boot and every one alive across an agent upgrade, until it exited, so every judgement made on a signature failed for them. On dogfood after the v0.7.0-rc.2 upgrade, Spotlight's `mds` and `mdworker_shared` reading Brave's `Local State` raised `credential_browser_store_read` as browser credential theft, although the rule skips them by their platform-qualified signing identifier: the records it judged had no signature. Operators' `team_id` and `signing_id` exclusions miss such processes for the same reason.

## What changes

- A snapshot `exec` carries the running process's signature: signing identifier, team, the kernel's code-signing flags and the platform-binary bit, read from the running code object by pid.
- A signature is attributed only when the process holding the pid started when the listed one did, so a reused pid cannot lend its signature to the listed process.

## Not changed

No wire change: snapshot execs carry the existing `code_signing` field, which the server already stores. Detection still ignores snapshot execs as events; the signature only reaches the rules through the process record.
