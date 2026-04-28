# Detection rules

This page is generated from `tools/gen-rule-docs` by walking the
`detection.Rule.Doc()` method on every rule registered in
`server/cmd/fleet-edr-server/main.go`. To refresh after changing a
rule's documentation, run:

```sh
go run ./tools/gen-rule-docs
```

Hand-edits to this file get overwritten on the next regeneration.

## Index

| Rule ID | Title | Severity | ATT&CK |
| --- | --- | --- | --- |
| [`suspicious_exec`](#suspicious_exec) | Suspicious exec chain (non-shell → shell → temp/network) | high | T1059, T1105 |
| [`persistence_launchagent`](#persistence_launchagent) | LaunchAgent persistence (launchctl load/bootstrap) | high | T1543.001 |
| [`dyld_insert`](#dyld_insert) | DYLD injection on exec | high | T1574.006 |
| [`shell_from_office`](#shell_from_office) | Shell spawned by Microsoft Office | high | T1566.001, T1059.004 |
| [`osascript_network_exec`](#osascript_network_exec) | AppleScript dropper (osascript → curl/wget → temp exec) | critical | T1059.002, T1105 |
| [`credential_keychain_dump`](#credential_keychain_dump) | Keychain dump (security dump-keychain) | high | T1555.001 |
| [`privilege_launchd_plist_write`](#privilege_launchd_plist_write) | LaunchDaemon plist drop (/Library/LaunchDaemons write) | high | T1543.004 |
| [`sudoers_tamper`](#sudoers_tamper) | Sudoers tamper (write to /etc/sudoers or /etc/sudoers.d/*) | high | T1548.003 |

## suspicious_exec

**Suspicious exec chain (non-shell → shell → temp/network)**  
Flags a non-shell process that spawns a shell which, within 30 seconds, exec's from /tmp or makes an outbound network connection.

| | |
| --- | --- |
| Rule ID | `suspicious_exec` |
| Severity | `high` |
| ATT&CK | [`T1059`](https://attack.mitre.org/techniques/T1059/), [`T1105`](https://attack.mitre.org/techniques/T1105/) |
| Event types | `exec`, `network_connect` |

### Description

Detects two related chain shapes that share a single attribution chain:

1. non-shell parent → shell child → temp-directory exec (e.g. `/tmp/payload`)
2. non-shell parent → shell child → outbound network_connect

The rule fires on the LAST link of the chain (the temp-exec or the network_connect) rather than the shell's exec. That makes it race-immune across the agent's flush boundaries — a chain that completes in ~150ms but straddles a 1-second flush boundary still resolves cleanly because the entire ancestor chain has already been ingested by the time the trigger event lands.

30 seconds is the temporal cap between the shell exec and the trigger event.

### Configuration

| Env var | Type | Default | Description |
| --- | --- | --- | --- |
| `EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST` | `csv-paths` | _(unset)_ | Comma-separated absolute parent-process paths the rule should treat as benign roots (both temp-exec and network arms). Canonical use: `/usr/libexec/sshd-session` on hosts where interactive SSH is normal. |

### Known false-positive sources

- Interactive SSH where an admin runs a script from /tmp and/or curls a tool. Use EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST to silence sshd-session if that's a routine workflow on the host class.
- Some Apple-signed installer-postflight scripts shell out to /tmp/ during package install.

### Limitations

- 30s window is hard-coded; long-tail post-shell activity is missed by design.
- Allowlisting a parent silences BOTH arms of the rule for that parent — the trade-off is documented on AllowedNonShellParents.

## persistence_launchagent

**LaunchAgent persistence (launchctl load/bootstrap)**  
Flags `launchctl load` / `launchctl bootstrap` of a plist under ~/Library/LaunchAgents or /Library/LaunchAgents.

| | |
| --- | --- |
| Rule ID | `persistence_launchagent` |
| Severity | `high` |
| ATT&CK | [`T1543.001`](https://attack.mitre.org/techniques/T1543/001/) |
| Event types | `exec` |

### Description

Detects the canonical user-domain persistence step on macOS: an attacker drops a plist into a LaunchAgents directory and then activates it via `launchctl load <plist>` or `launchctl bootstrap gui/<uid> <plist>`. We catch the activation rather than the file write so the alert ties to the moment the persistence becomes effective.

Argument parsing handles launch-domain specifiers (`gui/501`) preceding the plist path and tolerates flag-like args between `load` and the plist (`-w`, `-F`, etc.).

### Configuration

| Env var | Type | Default | Description |
| --- | --- | --- | --- |
| `EDR_LAUNCHAGENT_ALLOWLIST` | `csv-paths` | _(unset)_ | Comma-separated absolute plist paths the rule should silently accept. Use exact paths; case-sensitive. |

### Known false-positive sources

- MDM- or installer-provisioned LaunchAgents (Munki, Kandji, JumpCloud) loaded at deploy time. Allowlist their plist paths via EDR_LAUNCHAGENT_ALLOWLIST.
- Developer tools that register helper agents (Docker Desktop, Backblaze, etc.) on first launch.

### Limitations

- Does not cover `launchctl bootout` or `launchctl unload` — those undo persistence rather than create it.
- Does not catch direct plist writes that never get activated; pair with the privilege_launchd_plist_write rule for system-domain coverage.

## dyld_insert

**DYLD injection on exec**  
Flags exec where DYLD_INSERT_LIBRARIES or DYLD_LIBRARY_PATH is set in argv (shell-style or via env(1)).

| | |
| --- | --- |
| Rule ID | `dyld_insert` |
| Severity | `high` |
| ATT&CK | [`T1574.006`](https://attack.mitre.org/techniques/T1574/006/) |
| Event types | `exec` |

### Description

Detects the classic macOS code-injection primitive: launching a process with `DYLD_INSERT_LIBRARIES=…` or `DYLD_LIBRARY_PATH=…` set so dyld loads attacker-supplied dylibs into the new process before main(). The rule fires on the leading argv slot only — `VAR=value /path/to/bin` shell form, or `env VAR=value /path/to/bin` — so substring noise (curl POST data, echo, etc.) does not false-positive.

The matching dylib path is redacted in alert text (a sensitive payload location) but kept in the raw event payload for responders.

### Known false-positive sources

- Local development of code that itself uses DYLD_INSERT_LIBRARIES (rare; usually scoped to non-managed dev hosts).
- Apple-signed binaries are immune to DYLD_INSERT_LIBRARIES under SIP, but the rule still fires on the launch — investigate why an admin script is setting these vars at all.

### Limitations

- Inherited environment variables (set by a parent shell, not on the exec line) are invisible: ESF does not yet hand the agent the full env map. Tracked in Phase 4.
- DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_* are intentionally NOT matched — higher-FP, lower-signal. Extend dyldPrefixes if a pilot surfaces real abuse.

## shell_from_office

**Shell spawned by Microsoft Office**  
Flags any /bin/sh, /bin/bash, /bin/zsh (etc.) whose parent is Word, Excel, PowerPoint, or Outlook.

| | |
| --- | --- |
| Rule ID | `shell_from_office` |
| Severity | `high` |
| ATT&CK | [`T1566.001`](https://attack.mitre.org/techniques/T1566/001/), [`T1059.004`](https://attack.mitre.org/techniques/T1059/004/) |
| Event types | `exec` |

### Description

Detects the textbook post-phishing execution step: a macro-laden Office document opens, the macro shells out, and the second stage takes off from there. The match is on the parent process being one of the four standard macOS Office binaries (full path, not substring) and the child being a known shell.

Office apps almost never need to shell out in normal use; when they do, it's an admin-side automation that's worth surfacing anyway.

### Known false-positive sources

- Office's internal `Get Started` first-run flow has historically shelled out to fetch help content. Confirm by inspecting argv on the alert.
- Admin-driven user-environment scripts that template Office settings via shell.

### Limitations

- Does not catch non-shell payloads (osascript, python, ruby) launched directly from Office. Pair with osascript_network_exec for the AppleScript variant.
- Office binary path matching is exact: `/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word`. Apps installed elsewhere (e.g. on an external volume) are missed by design.

## osascript_network_exec

**AppleScript dropper (osascript → curl/wget → temp exec)**  
Critical-severity catch on the canonical macOS commodity-dropper chain: osascript fetches a stage-2 over the network and runs it from /tmp.

| | |
| --- | --- |
| Rule ID | `osascript_network_exec` |
| Severity | `critical` |
| ATT&CK | [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/), [`T1105`](https://attack.mitre.org/techniques/T1105/) |
| Event types | `exec` |

### Description

Fires on the LAST link of the chain — an exec from a temp directory whose process tree has both an osascript ancestor and a curl/wget sibling within the osascript's 30-second descendant window. This shape is the recognisable signature of macOS commodity malware staged via AppleScript.

Reverse-direction triggering is deliberate: by the time the temp-exec event lands, the entire ancestor chain has already been ingested and materialised by earlier batches, so the rule is race-immune. Forward triggering (fire on the osascript exec, look for descendants) misses chains that complete across an agent flush boundary.

The rule requires both halves of the chain to be present, so download-only or temp-exec-only flows do not fire here — those overlap with suspicious_exec.

### Known false-positive sources

- Internal automation that bootstraps tooling by scripting `curl … | sh` from osascript — extremely rare in managed fleets.

### Limitations

- 30-second descendant window is hard-coded; longer-running chains are missed by design.
- Does not cover Python URL fetches or AppleScript built-in URL access — only flags the explicit curl/wget shape.

## credential_keychain_dump

**Keychain dump (security dump-keychain)**  
Flags exec of /usr/bin/security dump-keychain — the canonical macOS Keychain export command.

| | |
| --- | --- |
| Rule ID | `credential_keychain_dump` |
| Severity | `high` |
| ATT&CK | [`T1555.001`](https://attack.mitre.org/techniques/T1555/001/) |
| Event types | `exec` |

### Description

Fires when a process invokes `/usr/bin/security` with the `dump-keychain` subcommand. That command exports Keychain entries (saved passwords, private keys) and is the macOS-native equivalent of credential-dumping tooling on Windows. Admin scripts virtually never invoke it; offensive playbooks do.

Match shape is exact-path + exact-subcommand to keep the rule high-precision. A shell wrapper (`sh -c "security dump-keychain"`) still surfaces because ESF emits a NOTIFY_EXEC for each execve(), so the security binary always shows up as its own exec event regardless of parent.

### Known false-positive sources

- An IT admin running a one-off keychain audit. Rare in managed fleets; confirm with the user before treating as benign.

### Limitations

- Does not cover Keychain reads via the Security framework (SecItemCopyMatching, etc.) or raw SQLite scrapes of login.keychain-db. Those paths are tracked for a future file-integrity rule.
- Does not cover adjacent enumerative subcommands (find-internet-password -w, find-generic-password -w) — left out for precision; add them to dumpKeychainArgTokens if a pilot fleet surfaces real abuse.

## privilege_launchd_plist_write

**LaunchDaemon plist drop (/Library/LaunchDaemons write)**  
Flags a non-platform-binary write to any *.plist directly under /Library/LaunchDaemons.

| | |
| --- | --- |
| Rule ID | `privilege_launchd_plist_write` |
| Severity | `high` |
| ATT&CK | [`T1543.004`](https://attack.mitre.org/techniques/T1543/004/) |
| Event types | `open_write` |

### Description

Detects the canonical system-domain persistence drop: writing a plist into `/Library/LaunchDaemons/`. Once that lands, the next `launchctl bootstrap system/<name>` (or a reboot) gives the attacker root-running persistence.

Paired with `persistence_launchagent` — that rule catches user-domain LaunchAgent activation via `launchctl load`, this one catches the system-domain drop step. We catch this at the file-write rather than the activation step because LaunchDaemon activation is often deferred until reboot.

To stay high-precision, writes by Apple-signed platform binaries (installd, system_installd, sysadminctl, package post-flight scripts) are skipped — they're the legitimate path. Non-Apple MDM agents (Munki, JumpCloud, Kandji's daemon) need their team ID allowlisted.

### Configuration

| Env var | Type | Default | Description |
| --- | --- | --- | --- |
| `EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST` | `csv-team-ids` | _(unset)_ | Comma-separated Apple Developer Program team IDs (10-character strings, e.g. `8VBZ3948LU`) whose code-signed binaries may write to /Library/LaunchDaemons silently. |

### Known false-positive sources

- Non-Apple MDM agent installations dropping their own LaunchDaemon. Allowlist the agent's signing team ID via EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST.
- Custom in-house pkg installers signed by your developer team — same allowlist applies.

### Limitations

- Atomic-rename writes (temp file + rename onto the destination) are missed; the extension does not subscribe to NOTIFY_RENAME today. Tracked for Phase 8.
- Drops via Apple platform binaries (e.g. `sudo cp` where cp is Apple-signed) are skipped here — pair with suspicious_exec for parent-shell visibility.

## sudoers_tamper

**Sudoers tamper (write to /etc/sudoers or /etc/sudoers.d/*)**  
Flags any non-allowlisted writer that opens /etc/sudoers or /etc/sudoers.d/* in write mode.

| | |
| --- | --- |
| Rule ID | `sudoers_tamper` |
| Severity | `high` |
| ATT&CK | [`T1548.003`](https://attack.mitre.org/techniques/T1548/003/) |
| Event types | `open_write` |

### Description

Detects an instant escalation primitive: writing to `/etc/sudoers` or any direct child of `/etc/sudoers.d/`. A successful tamper grants future shell sessions arbitrary command execution as root.

Unlike the persistence rules, this one deliberately does NOT key on Apple-signed platform binaries — the canonical attacker tools for sudoers tampering ARE platform binaries (cp, tee, redirected shells, even `sudo vi /etc/sudoers`), so a platform-binary filter would silence every realistic attack while admitting almost nothing of value. Operators tune via EDR_SUDOERS_WRITER_ALLOWLIST instead.

`visudo` and `sudoedit` use atomic-rename semantics and never open /etc/sudoers in write mode, so the rule does not see them at all.

### Configuration

| Env var | Type | Default | Description |
| --- | --- | --- | --- |
| `EDR_SUDOERS_WRITER_ALLOWLIST` | `csv-paths` | _(unset)_ | Comma-separated absolute writer-process paths to silently accept (e.g. `/usr/local/bin/ansible`). |

### Known false-positive sources

- Configuration-management agents (Ansible, Chef, Puppet, MDM-driven scripts) that drop a sudoers fragment under /etc/sudoers.d. Allowlist their absolute writer paths.

### Limitations

- Atomic-rename writes (write a temp file, rename onto /etc/sudoers) are missed: ESF NOTIFY_OPEN doesn't fire on rename, and the extension does not subscribe to NOTIFY_RENAME today. Tracked for Phase 8.

