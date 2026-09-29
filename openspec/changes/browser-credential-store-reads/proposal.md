## Why

Infostealers (Atomic, Poseidon, Banshee) are the most common macOS threat, and their core behavior is reading a browser's saved passwords and session cookies (MITRE T1555.003, issue #1187). Nothing on the host reports a read: the primary Endpoint Security client does not subscribe to opens at all (ADR-0008), and the file-tamper client keeps only destructive ones.

## What changes

- A third, NOTIFY-only Endpoint Security client in the security extension watches the credential files of Chrome, Brave, Edge, Arc, Vivaldi and Firefox, in every profile of every home: saved logins, form data, cookies, and the key material that decrypts them.
- Each file is muted as a literal path, found by listing each browser's profile directories, rather than muting the browser's directory as a prefix, which would wake the client for every file the browser touches. The accounts and profiles are re-read every five minutes.
- An open by a process signed by the browser's own team is dropped in the extension. Every other open is reported as an `open` event carrying its access mode. Apple's own tools are reported too, since `cp`, `sqlite3` and `ditto` are what stealers read the files with.

## Not changed

No wire change: the reads use the existing `open` event, and the server's file-write rules ignore it, because they read only opens with write access. The rule that raises an alert follows as its own change. Safari's cookies are not watched: they are TCC-protected and read constantly by Apple's WebKit processes, which need a filter of their own.
