## Why

SSH authorized keys (MITRE T1098.004) are one of the macOS techniques issue #1167 lists as uncovered, and no vendored Sigma rule covers them. A public key added to a user's `~/.ssh/authorized_keys` lets whoever holds the private key log in as that user, and keeps working after the password changes. The files live in each home, which the watched-path set can name since `~/` entries.

## What changes

- The server's default watched paths gain `~/.ssh/authorized_keys` and `~/.ssh/authorized_keys2`, the files sshd reads by default, so every host watches them in root's and every person's home.
- A new rule, `persistence_ssh_authorized_keys` (medium), fires when one of those files is written or has a file renamed onto it, naming the writer. Its logic is a detection block in its pack file.
- An operator waives a writer, such as a configuration-management agent, by a path glob on its path.

## Not changed

A key file named by a custom `AuthorizedKeysFile` is not watched unless an operator adds it. Removing a key is not reported. A host whose extension cannot expand `~/` entries watches neither file and reports nothing to this rule.
