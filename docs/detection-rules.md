# Detection rules

Rules marked with a **Source** carry that source's attribution and are reproduced unmodified. The upstream macOS corpus comes from [SigmaHQ](https://github.com/SigmaHQ/sigma) under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License); each rule names its own author.

This page is generated from `tools/gen-rule-docs` by reading the
`rulesapi.RuleMetadata.Doc` field on every rule registered in
`server/cmd/fleet-edr-server/main.go`. To refresh after changing a
rule's documentation, run:

```sh
go run ./tools/gen-rule-docs
```

Hand-edits to this file get overwritten on the next regeneration.

## Upstream rules not run

These rules are carried in the vendored upstream corpus but are not registered, because this sensor cannot run them. They are listed so an absent rule reads as a decision rather than an oversight.

| File | Why not |
| --- | --- |
| `imported/file_event/file_event_macos_emond_launch_daemon.yml` | category file_event maps to open, but this agent emits open only for /etc/sudoers paths (#301), so a file_event rule watching anything else could never fire |
| `imported/file_event/file_event_macos_susp_startup_item_created.yml` | category file_event maps to open, but this agent emits open only for /etc/sudoers paths (#301), so a file_event rule watching anything else could never fire |
| `imported/process_creation/proc_creation_macos_remote_access_tools_renamed_meshagent_execution.yml` | rule reads field(s) OriginalFileName which exec events do not supply; supported: CommandArguments, CommandLine, EnvAssignments, Image, ParentImage, Subcommand |

## Index

| Rule ID | Title | Severity | Default mode | ATT&CK |
| --- | --- | --- | --- | --- |
| [`suspicious_exec`](#suspicious_exec) | Suspicious exec chain | high | alert | T1059, T1105 |
| [`persistence_launchagent`](#persistence_launchagent) | LaunchAgent persistence | high | alert | T1543.001 |
| [`dyld_insert`](#dyld_insert) | DYLD injection on exec | high | alert | T1574.006 |
| [`shell_from_office`](#shell_from_office) | Shell spawned by Microsoft Office | high | alert | T1566.001, T1059.004 |
| [`osascript_network_exec`](#osascript_network_exec) | AppleScript dropper | critical | alert | T1059.002, T1105 |
| [`credential_keychain_dump`](#credential_keychain_dump) | Keychain credential dump | high | alert | T1555.001 |
| [`privilege_launchd_plist_write`](#privilege_launchd_plist_write) | LaunchDaemon persistence | high | alert | T1543.004 |
| [`sudoers_tamper`](#sudoers_tamper) | Sudoers tamper | high | alert | T1548.003 |
| [`dns_c2_beacon`](#dns_c2_beacon) | DNS C2 beacon | high | alert | T1071.004, T1568.002 |
| [`sensor_tamper`](#sensor_tamper) | EDR sensor disabled | high | alert | T1562.001 |
| [`proc_creation_macos_applescript`](#proc_creation_macos_applescript) | MacOS Scripting Interpreter AppleScript | medium | monitor | T1059.002 |
| [`proc_creation_macos_base64_decode`](#proc_creation_macos_base64_decode) | Decode Base64 Encoded Text -MacOs | low | monitor | T1027 |
| [`proc_creation_macos_binary_padding`](#proc_creation_macos_binary_padding) | Binary Padding - MacOS | high | monitor | T1027.001 |
| [`proc_creation_macos_change_file_time_attr`](#proc_creation_macos_change_file_time_attr) | File Time Attribute Change | medium | monitor | T1070.006 |
| [`proc_creation_macos_chflags_hidden_flag`](#proc_creation_macos_chflags_hidden_flag) | Hidden Flag Set On File/Directory Via Chflags - MacOS | medium | monitor | T1218, T1564.004, T1552.001, T1105 |
| [`proc_creation_macos_clear_system_logs`](#proc_creation_macos_clear_system_logs) | Indicator Removal on Host - Clear Mac System Logs | medium | monitor | T1685.006 |
| [`proc_creation_macos_clipboard_access_via_osascript`](#proc_creation_macos_clipboard_access_via_osascript) | Clipboard Access Via OSAScript | medium | monitor | T1115, T1059.002 |
| [`proc_creation_macos_create_account`](#proc_creation_macos_create_account) | Creation Of A Local User Account | low | monitor | T1136.001 |
| [`proc_creation_macos_create_hidden_account`](#proc_creation_macos_create_hidden_account) | Hidden User Creation | medium | monitor | T1564.002 |
| [`proc_creation_macos_creds_from_keychain`](#proc_creation_macos_creds_from_keychain) | Credentials from Password Stores - Keychain | medium | monitor | T1555.001 |
| [`proc_creation_macos_csrutil_disable`](#proc_creation_macos_csrutil_disable) | System Integrity Protection (SIP) Disabled | medium | monitor | T1518.001 |
| [`proc_creation_macos_csrutil_status`](#proc_creation_macos_csrutil_status) | System Integrity Protection (SIP) Enumeration | low | monitor | T1518.001 |
| [`proc_creation_macos_disable_security_tools`](#proc_creation_macos_disable_security_tools) | Disable Security Tools | medium | monitor | T1685 |
| [`proc_creation_macos_dscl_add_user_to_admin_group`](#proc_creation_macos_dscl_add_user_to_admin_group) | User Added To Admin Group Via Dscl | medium | monitor | T1078.003 |
| [`proc_creation_macos_dseditgroup_add_to_admin_group`](#proc_creation_macos_dseditgroup_add_to_admin_group) | User Added To Admin Group Via DseditGroup | medium | monitor | T1078.003 |
| [`proc_creation_macos_dsenableroot_enable_root_account`](#proc_creation_macos_dsenableroot_enable_root_account) | Root Account Enable Via Dsenableroot | medium | monitor | T1078, T1078.001, T1078.003 |
| [`proc_creation_macos_file_and_directory_discovery`](#proc_creation_macos_file_and_directory_discovery) | File and Directory Discovery - MacOS | low | monitor | T1083 |
| [`proc_creation_macos_find_cred_in_files`](#proc_creation_macos_find_cred_in_files) | Credentials In Files | high | monitor | T1552.001 |
| [`proc_creation_macos_gui_input_capture`](#proc_creation_macos_gui_input_capture) | GUI Input Capture - macOS | low | monitor | T1056.002 |
| [`proc_creation_macos_hdiutil_create`](#proc_creation_macos_hdiutil_create) | Disk Image Creation Via Hdiutil - MacOS | medium | monitor |  |
| [`proc_creation_macos_hdiutil_mount`](#proc_creation_macos_hdiutil_mount) | Disk Image Mounting Via Hdiutil - MacOS | medium | monitor | T1566.001, T1560.001 |
| [`proc_creation_macos_installer_susp_child_process`](#proc_creation_macos_installer_susp_child_process) | Suspicious Installer Package Child Process | medium | monitor | T1059, T1059.007, T1071, T1071.001 |
| [`proc_creation_macos_ioreg_discovery`](#proc_creation_macos_ioreg_discovery) | System Information Discovery Using Ioreg | medium | monitor | T1082 |
| [`proc_creation_macos_jamf_susp_child`](#proc_creation_macos_jamf_susp_child) | JAMF MDM Potential Suspicious Child Process | medium | monitor |  |
| [`proc_creation_macos_jamf_usage`](#proc_creation_macos_jamf_usage) | JAMF MDM Execution | low | monitor |  |
| [`proc_creation_macos_jxa_in_memory_execution`](#proc_creation_macos_jxa_in_memory_execution) | JXA In-memory Execution Via OSAScript | high | monitor | T1059.002, T1059.007 |
| [`proc_creation_macos_launchctl_execution`](#proc_creation_macos_launchctl_execution) | Launch Agent/Daemon Execution Via Launchctl | medium | monitor | T1569.001, T1543.001, T1543.004 |
| [`proc_creation_macos_local_account`](#proc_creation_macos_local_account) | Local System Accounts Discovery - MacOs | low | monitor | T1087.001 |
| [`proc_creation_macos_local_groups`](#proc_creation_macos_local_groups) | Local Groups Discovery - MacOs | low | monitor | T1069.001 |
| [`proc_creation_macos_network_service_scanning`](#proc_creation_macos_network_service_scanning) | MacOS Network Service Scanning | low | monitor | T1046 |
| [`proc_creation_macos_network_sniffing`](#proc_creation_macos_network_sniffing) | Network Sniffing - MacOs | low | monitor | T1040 |
| [`proc_creation_macos_nscurl_usage`](#proc_creation_macos_nscurl_usage) | File Download Via Nscurl - MacOS | medium | monitor | T1105 |
| [`proc_creation_macos_office_susp_child_processes`](#proc_creation_macos_office_susp_child_processes) | Suspicious Microsoft Office Child Process - MacOS | high | monitor | T1059.002, T1137.002, T1204.002 |
| [`proc_creation_macos_osacompile_runonly_execution`](#proc_creation_macos_osacompile_runonly_execution) | OSACompile Run-Only Execution | high | monitor | T1059.002 |
| [`proc_creation_macos_payload_decoded_and_decrypted`](#proc_creation_macos_payload_decoded_and_decrypted) | Payload Decoded and Decrypted via Built-in Utilities | medium | monitor | T1059, T1204, T1140 |
| [`proc_creation_macos_persistence_via_plistbuddy`](#proc_creation_macos_persistence_via_plistbuddy) | Potential Persistence Via PlistBuddy | high | monitor | T1543.001, T1543.004 |
| [`proc_creation_macos_remote_access_tools_meshagent_arguments`](#proc_creation_macos_remote_access_tools_meshagent_arguments) | Remote Access Tool - Potential MeshAgent Execution - MacOS | medium | monitor | T1219.002 |
| [`proc_creation_macos_remote_access_tools_teamviewer_incoming_connection`](#proc_creation_macos_remote_access_tools_teamviewer_incoming_connection) | Remote Access Tool - Team Viewer Session Started On MacOS Host | low | monitor | T1133 |
| [`proc_creation_macos_remote_system_discovery`](#proc_creation_macos_remote_system_discovery) | Macos Remote System Discovery | low | monitor | T1018 |
| [`proc_creation_macos_schedule_task_job_cron`](#proc_creation_macos_schedule_task_job_cron) | Scheduled Cron Task/Job - MacOs | medium | monitor | T1053.003 |
| [`proc_creation_macos_screencapture`](#proc_creation_macos_screencapture) | Screen Capture - macOS | low | monitor | T1113 |
| [`proc_creation_macos_security_software_discovery`](#proc_creation_macos_security_software_discovery) | Security Software Discovery - MacOs | medium | monitor | T1518.001 |
| [`proc_creation_macos_space_after_filename`](#proc_creation_macos_space_after_filename) | Space After Filename - macOS | low | monitor | T1036.006 |
| [`proc_creation_macos_split_file_into_pieces`](#proc_creation_macos_split_file_into_pieces) | Split A File Into Pieces | low | monitor | T1030 |
| [`proc_creation_macos_susp_browser_child_process`](#proc_creation_macos_susp_browser_child_process) | Suspicious Browser Child Process - MacOS | medium | monitor | T1189, T1203, T1059 |
| [`proc_creation_macos_susp_execution_macos_script_editor`](#proc_creation_macos_susp_execution_macos_script_editor) | Suspicious Execution via macOS Script Editor | medium | monitor | T1566, T1566.002, T1059, T1059.002, T1204, T1204.001, T1553 |
| [`proc_creation_macos_susp_find_execution`](#proc_creation_macos_susp_find_execution) | Potential Discovery Activity Using Find - MacOS | medium | monitor | T1083 |
| [`proc_creation_macos_susp_histfile_operations`](#proc_creation_macos_susp_histfile_operations) | Suspicious History File Operations | medium | monitor | T1552.003 |
| [`proc_creation_macos_susp_in_memory_download_and_compile`](#proc_creation_macos_susp_in_memory_download_and_compile) | Potential In-Memory Download And Compile Of Payloads | medium | monitor | T1059.007, T1105 |
| [`proc_creation_macos_susp_macos_firmware_activity`](#proc_creation_macos_susp_macos_firmware_activity) | Suspicious MacOS Firmware Activity | medium | monitor |  |
| [`proc_creation_macos_susp_system_network_discovery`](#proc_creation_macos_susp_system_network_discovery) | System Network Discovery - macOS | low | monitor | T1016 |
| [`proc_creation_macos_suspicious_applet_behaviour`](#proc_creation_macos_suspicious_applet_behaviour) | Osacompile Execution By Potentially Suspicious Applet/Osascript | medium | monitor | T1059.002 |
| [`proc_creation_macos_swvers_discovery`](#proc_creation_macos_swvers_discovery) | System Information Discovery Using sw_vers | medium | monitor | T1082 |
| [`proc_creation_macos_sysadminctl_add_user_to_admin_group`](#proc_creation_macos_sysadminctl_add_user_to_admin_group) | User Added To Admin Group Via Sysadminctl | medium | monitor | T1078.003 |
| [`proc_creation_macos_sysadminctl_enable_guest_account`](#proc_creation_macos_sysadminctl_enable_guest_account) | Guest Account Enabled Via Sysadminctl | low | monitor | T1078, T1078.001 |
| [`proc_creation_macos_sysctl_discovery`](#proc_creation_macos_sysctl_discovery) | System Information Discovery Via Sysctl - MacOS | medium | monitor | T1497.001, T1082 |
| [`proc_creation_macos_system_network_connections_discovery`](#proc_creation_macos_system_network_connections_discovery) | System Network Connections Discovery - MacOs | low | monitor | T1049 |
| [`proc_creation_macos_system_profiler_discovery`](#proc_creation_macos_system_profiler_discovery) | System Information Discovery Using System_Profiler | medium | monitor | T1082, T1497.001 |
| [`proc_creation_macos_system_shutdown_reboot`](#proc_creation_macos_system_shutdown_reboot) | System Shutdown/Reboot - MacOs | low | monitor | T1529 |
| [`proc_creation_macos_tail_base64_decode_from_image`](#proc_creation_macos_tail_base64_decode_from_image) | Potential Base64 Decoded From Images | high | monitor | T1140 |
| [`proc_creation_macos_tmutil_delete_backup`](#proc_creation_macos_tmutil_delete_backup) | Time Machine Backup Deletion Attempt Via Tmutil - MacOS | medium | monitor | T1490 |
| [`proc_creation_macos_tmutil_disable_backup`](#proc_creation_macos_tmutil_disable_backup) | Time Machine Backup Disabled Via Tmutil - MacOS | medium | monitor | T1490 |
| [`proc_creation_macos_tmutil_exclude_file_from_backup`](#proc_creation_macos_tmutil_exclude_file_from_backup) | New File Exclusion Added To Time Machine Via Tmutil - MacOS | medium | monitor | T1490 |
| [`proc_creation_macos_wizardupdate_malware_infection`](#proc_creation_macos_wizardupdate_malware_infection) | Potential WizardUpdate Malware Infection | high | monitor |  |
| [`proc_creation_macos_xattr_gatekeeper_bypass`](#proc_creation_macos_xattr_gatekeeper_bypass) | Gatekeeper Bypass via Xattr | low | monitor | T1553.001 |
| [`proc_creation_macos_xcsset_malware_infection`](#proc_creation_macos_xcsset_malware_infection) | Potential XCSSET Malware Infection | medium | monitor |  |

## suspicious_exec

**Suspicious exec chain**  
Flags a non-shell process that spawns a shell which, within 30 seconds, execs from /tmp or makes an outbound network connection.

| | |
| --- | --- |
| Rule ID | `suspicious_exec` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1059`](https://attack.mitre.org/techniques/T1059/), [`T1105`](https://attack.mitre.org/techniques/T1105/) |
| Event types | `exec`, `network_connect` |

### Description

Detects two related chain shapes that share a single attribution chain:

1. non-shell parent → shell child → temp-directory exec (e.g. `/tmp/payload`)
2. non-shell parent → shell child → outbound network_connect

The rule fires on the LAST link of the chain (the temp-exec or the network_connect) rather than the shell's exec. That makes it race-immune across the agent's flush boundaries: a chain that completes in ~150ms but straddles a 1-second flush boundary still resolves cleanly because the entire ancestor chain has already been ingested by the time the trigger event lands.

30 seconds is the temporal cap between the shell exec and the trigger event.

### Known false-positive sources

- Interactive SSH where an admin runs a script from /tmp and/or curls a tool. Add a parent-path-glob exclusion for `/usr/libexec/sshd-session` via the detection-config surface if that's a routine workflow on the host class.
- Developer tooling that shells out and connects (Claude Code, lefthook git hooks, git, IDEs). These install under version-stamped paths, so add a parent-path-glob exclusion such as `*/claude/versions/*` or `*/lefthook_*` that survives upgrades.
- Some Apple-signed installer-postflight scripts shell out to /tmp/ during package install.

### Limitations

- The window bounds how long after the shell exec a trigger still counts; long-tail post-shell activity is missed by design. Set in x-engine.params.window.
- A parent-path-glob exclusion silences BOTH arms of the rule for that parent.
- An outbound DNS lookup (port 53) to a local-resolver-class address (loopback, RFC1918, link-local, CGNAT 100.64.0.0/10, IPv6 ULA/link-local) is treated as name resolution and does not trigger the network arm; a DNS lookup to a publicly routable resolver still fires.

## persistence_launchagent

**LaunchAgent persistence**  
Flags `launchctl load` / `launchctl bootstrap` of a plist under ~/Library/LaunchAgents or /Library/LaunchAgents.

| | |
| --- | --- |
| Rule ID | `persistence_launchagent` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1543.001`](https://attack.mitre.org/techniques/T1543/001/) |
| Event types | `exec` |

### Description

Detects the canonical user-domain persistence step on macOS: an attacker drops a plist into a LaunchAgents directory and then activates it via `launchctl load <plist>` or `launchctl bootstrap gui/<uid> <plist>`. We catch the activation rather than the file write so the alert ties to the moment the persistence becomes effective.

Argument parsing handles launch-domain specifiers (`gui/501`) preceding the plist path and tolerates flag-like args between `load` and the plist (`-w`, `-F`, etc.).

### Known false-positive sources

- MDM- or installer-provisioned LaunchAgents (Munki, Kandji, JumpCloud) loaded at deploy time. Add a path-glob exclusion for their plist paths via the detection-config surface.
- Developer tools that register helper agents (Docker Desktop, Backblaze, etc.) on first launch.

### Limitations

- Does not cover `launchctl bootout` or `launchctl unload`: those undo persistence rather than create it.
- Does not catch direct plist writes that never get activated; pair with the privilege_launchd_plist_write rule for system-domain coverage.

## dyld_insert

**DYLD injection on exec**  
Flags exec where DYLD_INSERT_LIBRARIES or DYLD_LIBRARY_PATH is set in argv (shell-style or via env(1)).

| | |
| --- | --- |
| Rule ID | `dyld_insert` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1574.006`](https://attack.mitre.org/techniques/T1574/006/) |
| Event types | `exec` |

### Description

Detects the classic macOS code-injection primitive: launching a process with `DYLD_INSERT_LIBRARIES=…` or `DYLD_LIBRARY_PATH=…` set so dyld loads attacker-supplied dylibs into the new process before main(). The rule fires on the leading argv slot only (the `VAR=value /path/to/bin` shell form, or the `env VAR=value /path/to/bin` invocation), so substring noise (curl POST data, echo, etc.) does not false-positive.

The matching dylib path is redacted in alert text (a sensitive payload location) but kept in the raw event payload for responders.

### Known false-positive sources

- Local development of code that itself uses DYLD_INSERT_LIBRARIES (rare; usually scoped to non-managed dev hosts).
- Apple-signed binaries are immune to DYLD_INSERT_LIBRARIES under SIP, but the rule still fires on the launch: investigate why an admin script is setting these vars at all.

### Limitations

- Inherited environment variables (set by a parent shell, not on the exec line) are invisible: ESF does not yet hand the agent the full env map. Tracked as future work.
- DYLD_FRAMEWORK_PATH and DYLD_FALLBACK_* are intentionally NOT matched: higher-FP, lower-signal. Add them to the detection block in the rule's pack file if a pilot surfaces real abuse; the Go prefix list only names the matched variable in the alert.

## shell_from_office

**Shell spawned by Microsoft Office**  
Flags any /bin/sh, /bin/bash, /bin/zsh (etc.) whose parent is Word, Excel, PowerPoint, or Outlook.

| | |
| --- | --- |
| Rule ID | `shell_from_office` |
| Severity | `high` |
| Default mode | `alert` |
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

**AppleScript dropper**  
Critical-severity catch on the canonical macOS commodity-dropper chain: osascript fetches a stage-2 over the network and runs it from /tmp.

| | |
| --- | --- |
| Rule ID | `osascript_network_exec` |
| Severity | `critical` |
| Default mode | `alert` |
| ATT&CK | [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/), [`T1105`](https://attack.mitre.org/techniques/T1105/) |
| Event types | `exec` |

### Description

Fires on the LAST link of the chain: an exec from a temp directory whose process tree has both an osascript ancestor and a curl/wget sibling within the osascript's 30-second descendant window. This shape is the recognisable signature of macOS commodity malware staged via AppleScript.

Reverse-direction triggering is deliberate: by the time the temp-exec event lands, the entire ancestor chain has already been ingested and materialised by earlier batches, so the rule is race-immune. Forward triggering (fire on the osascript exec, look for descendants) misses chains that complete across an agent flush boundary.

The rule requires both halves of the chain to be present, so download-only or temp-exec-only flows do not fire here: those overlap with suspicious_exec.

### Known false-positive sources

- Internal automation that bootstraps tooling by scripting `curl … | sh` from osascript: extremely rare in managed fleets.

### Limitations

- The descendant window bounds how long after the osascript exec a stage-2 still counts; longer-running chains are missed by design. Set in x-engine.params.window.
- Does not cover Python URL fetches or AppleScript built-in URL access: only flags the explicit curl/wget shape.

## credential_keychain_dump

**Keychain credential dump**  
Flags exec of /usr/bin/security dump-keychain: the canonical macOS Keychain export command.

| | |
| --- | --- |
| Rule ID | `credential_keychain_dump` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1555.001`](https://attack.mitre.org/techniques/T1555/001/) |
| Event types | `exec` |

### Description

Fires when a process invokes `/usr/bin/security` with the `dump-keychain` subcommand. That command exports Keychain entries (saved passwords, private keys) and is the macOS-native equivalent of credential-dumping tooling on Windows. Admin scripts virtually never invoke it; offensive playbooks do.

Match shape is exact-path + exact-subcommand to keep the rule high-precision. A shell wrapper (`sh -c "security dump-keychain"`) still surfaces because ESF emits a NOTIFY_EXEC for each execve(), so the security binary always shows up as its own exec event regardless of parent.

### Known false-positive sources

- An IT admin running a one-off keychain audit. Rare in managed fleets; confirm with the user before treating as benign.

### Limitations

- Does not cover Keychain reads via the Security framework (SecItemCopyMatching, etc.) or raw SQLite scrapes of login.keychain-db. Those paths are tracked for a future file-integrity rule.
- Does not cover adjacent enumerative subcommands (find-internet-password -w, find-generic-password -w); left out for precision; add them to the detection block in the rule's pack file if a pilot fleet surfaces real abuse.

## privilege_launchd_plist_write

**LaunchDaemon persistence**  
Flags a system-domain LaunchDaemon whose registered executable is not an Apple platform binary and not allowlisted.

| | |
| --- | --- |
| Rule ID | `privilege_launchd_plist_write` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1543.004`](https://attack.mitre.org/techniques/T1543/004/) |
| Event types | `btm_launch_item_add` |

### Description

Detects the canonical system-domain persistence vector (T1543.004): a LaunchDaemon being registered with macOS Background Task Management. Once registered, the next `launchctl bootstrap system/<name>` (or a reboot) gives the attacker root-running persistence.

Keyed on the high-level `BTM_LAUNCH_ITEM_ADD` event (`item_type=daemon`) rather than a raw file write, so the registration is caught no matter how the plist landed on disk (direct write, atomic temp-file+rename, copy), which a file-write rule can miss.

The decision keys on the REGISTERED EXECUTABLE's code-signing, not on who registered it: a `launchctl bootstrap` is always instigated by Apple's `smd`, so the instigator cannot discriminate. A daemon whose executable is an Apple platform binary, MDM-managed, or signed by an allowlisted vendor team ID is skipped; an ad-hoc, unsigned, or unknown-vendor executable fires. Paired with `persistence_launchagent` (user-domain LaunchAgents).

Notarization is deliberately NOT a trust signal: it is an automated Apple scan, not an endorsement (Apple has notarized malware), and is not checkable network-free on the ES callback thread. Trust is the operator's team-ID allowlist; notarization, if ever used, belongs in a server-side reputation layer off the hot path.

### Known false-positive sources

- Non-Apple vendor app installing its own LaunchDaemon (a niche VPN, an in-house agent). Add a team_id exclusion for the vendor's signing team ID via the detection-config surface.
- Custom in-house pkg installers signed by an unexcluded developer team: add a team_id exclusion for that team ID.

### Limitations

- BTM fires at item registration, not at the raw file-drop moment. A plist dropped on disk but never registered/loaded does not surface until registration (often deferred to reboot).
- Registrations whose executable code-signing cannot be read (executable absent or unreadable at registration) are skipped to stay high-precision.

## sudoers_tamper

**Sudoers tamper**  
Flags any non-allowlisted writer that opens /etc/sudoers or /etc/sudoers.d/* in write mode.

| | |
| --- | --- |
| Rule ID | `sudoers_tamper` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1548.003`](https://attack.mitre.org/techniques/T1548/003/) |
| Event types | `open` |

### Description

Detects an instant escalation primitive: writing to `/etc/sudoers` or any direct child of `/etc/sudoers.d/`. A successful tamper grants future shell sessions arbitrary command execution as root.

Unlike the persistence rules, this one deliberately does NOT key on Apple-signed platform binaries: the canonical attacker tools for sudoers tampering ARE platform binaries (cp, tee, redirected shells, even `sudo vi /etc/sudoers`), so a platform-binary filter would silence every realistic attack while admitting almost nothing of value. Operators tune with a path-glob exclusion via the detection-config surface instead.

`visudo` and `sudoedit` use atomic-rename semantics and never open /etc/sudoers in write mode, so the rule does not see them at all.

### Known false-positive sources

- Configuration-management agents (Ansible, Chef, Puppet, MDM-driven scripts) that drop a sudoers fragment under /etc/sudoers.d. Add a path-glob exclusion for their absolute writer paths.

### Limitations

- Atomic-rename writes (write a temp file, rename onto /etc/sudoers) are missed: ESF NOTIFY_OPEN doesn't fire on rename, and the extension does not subscribe to NOTIFY_RENAME today. Tracked as future work.

## dns_c2_beacon

**DNS C2 beacon**  
Flags a program that looks up a domain name and then connects to the address that lookup returned, when that program was launched from a suspicious location such as a temporary or world-writable folder. This is the classic "malware phoning home" shape, and the alert ties three normally separate signals into one finding: the program launch, the DNS lookup, and the outbound connection.

| | |
| --- | --- |
| Rule ID | `dns_c2_beacon` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1071.004`](https://attack.mitre.org/techniques/T1071/004/), [`T1568.002`](https://attack.mitre.org/techniques/T1568/002/) |
| Event types | `network_connect`, `dns_query`, `exec` |

### Description

Fires on the last link of the chain: an outbound network connection from a program that was launched out of a temporary or world-writable path and had earlier looked up a domain whose resolved addresses include the one now being connected to. The single finding cites both the DNS lookup and the outbound connection, and is attributed to the program that launched, so an analyst sees the whole launch -> lookup -> connection chain in one alert.

Triggering on the connection (rather than on the lookup) is deliberate and avoids races: by the time the connection lands, the program's DNS lookups are already recorded, so the rule keeps no state between event batches. The DNS lookup and the connection are reported by the same network extension and share its clock, so the lookup-then-connect window is measured directly on their timestamps.

A high-entropy, algorithmically generated domain name (the kind produced by a domain-generation algorithm) raises the finding to Critical and adds the DGA technique. Ordinary browser traffic does not fire this rule: it only considers programs launched from a suspicious location, which a browser is not.

### Known false-positive sources

- A legitimate tool staged in a temporary path that looks up a hostname and connects to it. This is rare on managed fleets; allowlist the path if it recurs.

### Limitations

- Sees plain UDP/TCP DNS only. Encrypted DNS (DoH/DoT) bypasses the proxy and is not correlated.
- The current detection requires the program to have been launched from a temporary or world-writable path. Detecting beacons started by a scripting interpreter that is running non-interactively (for example, a shell script with no terminal) is a planned addition.
- The lookup-then-connect window is bounded (currently 30 seconds). A beacon that looks up its domain far in advance of connecting is missed by design.

## sensor_tamper

**EDR sensor disabled**  
Flags one of the EDR's own capture providers stopping without coming back within a few seconds.

| | |
| --- | --- |
| Rule ID | `sensor_tamper` |
| Severity | `high` |
| Default mode | `alert` |
| ATT&CK | [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/) |
| Event types | `sensor_provider_transition` |

### Description

Detects tampering with the EDR itself. A capture provider (the content filter or the DNS proxy) stopping means the host stops reporting the telemetry that provider carries, so an attacker who can switch it off can work unobserved.

The agent restores a stopped provider automatically, in about 35 seconds. That repair is why the rule exists rather than why it is unnecessary: agent health only reports what is true now, so once the provider is back the health view reads healthy and nothing records that it was ever off. The alert is the durable account.

An agent upgrade also stops providers, as part of replacing the system extension, and the platform reports the same stop reason for that as for somebody switching capture off. The rule separates them by how fast capture resumes: an upgrade's replacement provider runs about a second later, while a stop that needed the automatic repair takes tens of seconds. A provider that resumes within a few seconds is therefore not reported.

A provider an operator has deliberately turned off (the DNS proxy is optional) is reported as absent rather than stopped and never reaches this rule.

### Known false-positive sources

- An upgrade whose replacement provider takes more than a few seconds to start. The upgrade cutover measured on a live host resumed capture in about a second; a host slow enough to exceed the window would also be a host that was genuinely not capturing for that long.

### Limitations

- Reports that capture stopped, not whether it was restored. The repair (or its failure) is carried by the following transition events on the host's timeline rather than by the alert.
- An attacker who stops a provider and prevents the agent from reporting it at all (killing the agent, or blocking upload) produces no transition event and so no alert. That absence is covered by host health going stale, not by this rule.

## proc_creation_macos_applescript

**MacOS Scripting Interpreter AppleScript**  
MacOS Scripting Interpreter AppleScript

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_applescript` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/) |
| Event types | `exec` |

### Description

Detects execution of AppleScript of the macOS scripting language AppleScript.

### Known false-positive sources

- Application installers might contain scripts as part of the installation process.

## proc_creation_macos_base64_decode

**Decode Base64 Encoded Text -MacOs**  
Decode Base64 Encoded Text -MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_base64_decode` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniil Yugoslavskiy, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1027`](https://attack.mitre.org/techniques/T1027/) |
| Event types | `exec` |

### Description

Detects usage of base64 utility to decode arbitrary base64-encoded text

### Known false-positive sources

- Legitimate activities

## proc_creation_macos_binary_padding

**Binary Padding - MacOS**  
Binary Padding - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_binary_padding` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Igor Fits, Mikhail Larin, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1027.001`](https://attack.mitre.org/techniques/T1027/001/) |
| Event types | `exec` |

### Description

Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.

### Known false-positive sources

- Legitimate script work

## proc_creation_macos_change_file_time_attr

**File Time Attribute Change**  
File Time Attribute Change

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_change_file_time_attr` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Igor Fits, Mikhail Larin, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1070.006`](https://attack.mitre.org/techniques/T1070/006/) |
| Event types | `exec` |

### Description

Detect file time attribute change to hide new or changes to existing files

### Known false-positive sources

- Unknown

## proc_creation_macos_chflags_hidden_flag

**Hidden Flag Set On File/Directory Via Chflags - MacOS**  
Hidden Flag Set On File/Directory Via Chflags - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_chflags_hidden_flag` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Omar Khaled (@beacon_exe) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1218`](https://attack.mitre.org/techniques/T1218/), [`T1564.004`](https://attack.mitre.org/techniques/T1564/004/), [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/), [`T1105`](https://attack.mitre.org/techniques/T1105/) |
| Event types | `exec` |

### Description

Detects the execution of the "chflags" utility with the "hidden" flag, in order to hide files on MacOS.
When a file or directory has this hidden flag set, it becomes invisible to the default file listing commands and in graphical file browsers.


### Known false-positive sources

- Legitimate usage of chflags by administrators and users.

## proc_creation_macos_clear_system_logs

**Indicator Removal on Host - Clear Mac System Logs**  
Indicator Removal on Host - Clear Mac System Logs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_clear_system_logs` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by remotephone, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1685.006`](https://attack.mitre.org/techniques/T1685/006/) |
| Event types | `exec` |

### Description

Detects deletion of local audit logs

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_clipboard_access_via_osascript

**Clipboard Access Via OSAScript**  
Clipboard Access Via OSAScript

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_clipboard_access_via_osascript` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1115`](https://attack.mitre.org/techniques/T1115/), [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/) |
| Event types | `exec` |

### Description

Detects access to clipboard content via osascript, which may be used for data collection but also occurs in legitimate clipboard utilities and automation scripts

### Known false-positive sources

- Legitimate clipboard utilities and automation scripts that read or write clipboard content
- Developer tools and IDEs that use osascript for clipboard integration

## proc_creation_macos_create_account

**Creation Of A Local User Account**  
Creation Of A Local User Account

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_create_account` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1136.001`](https://attack.mitre.org/techniques/T1136/001/) |
| Event types | `exec` |

### Description

Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_create_hidden_account

**Hidden User Creation**  
Hidden User Creation

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_create_hidden_account` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniil Yugoslavskiy, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1564.002`](https://attack.mitre.org/techniques/T1564/002/) |
| Event types | `exec` |

### Description

Detects creation of a hidden user account on macOS (UserID < 500) or with IsHidden option

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_creds_from_keychain

**Credentials from Password Stores - Keychain**  
Credentials from Password Stores - Keychain

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_creds_from_keychain` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Tim Ismilyaev, oscd.community, Florian Roth (Nextron Systems) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1555.001`](https://attack.mitre.org/techniques/T1555/001/) |
| Event types | `exec` |

### Description

Detects passwords dumps from Keychain

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_csrutil_disable

**System Integrity Protection (SIP) Disabled**  
System Integrity Protection (SIP) Disabled

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_csrutil_disable` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Joseliyo Sanchez, @Joseliyo_Jstnk |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1518.001`](https://attack.mitre.org/techniques/T1518/001/) |
| Event types | `exec` |

### Description

Detects the use of csrutil to disable the Configure System Integrity Protection (SIP). This technique is used in post-exploit scenarios.


### Known false-positive sources

- Unknown

## proc_creation_macos_csrutil_status

**System Integrity Protection (SIP) Enumeration**  
System Integrity Protection (SIP) Enumeration

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_csrutil_status` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Joseliyo Sanchez, @Joseliyo_Jstnk |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1518.001`](https://attack.mitre.org/techniques/T1518/001/) |
| Event types | `exec` |

### Description

Detects the use of csrutil to view the Configure System Integrity Protection (SIP) status. This technique is used in post-exploit scenarios.


### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_disable_security_tools

**Disable Security Tools**  
Disable Security Tools

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_disable_security_tools` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniil Yugoslavskiy, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1685`](https://attack.mitre.org/techniques/T1685/) |
| Event types | `exec` |

### Description

Detects disabling security tools

### Known false-positive sources

- Legitimate activities

## proc_creation_macos_dscl_add_user_to_admin_group

**User Added To Admin Group Via Dscl**  
User Added To Admin Group Via Dscl

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_dscl_add_user_to_admin_group` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1078.003`](https://attack.mitre.org/techniques/T1078/003/) |
| Event types | `exec` |

### Description

Detects attempts to create and add an account to the admin group via "dscl"

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_dseditgroup_add_to_admin_group

**User Added To Admin Group Via DseditGroup**  
User Added To Admin Group Via DseditGroup

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_dseditgroup_add_to_admin_group` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1078.003`](https://attack.mitre.org/techniques/T1078/003/) |
| Event types | `exec` |

### Description

Detects attempts to create and/or add an account to the admin group, thus granting admin privileges.

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_dsenableroot_enable_root_account

**Root Account Enable Via Dsenableroot**  
Root Account Enable Via Dsenableroot

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_dsenableroot_enable_root_account` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1078`](https://attack.mitre.org/techniques/T1078/), [`T1078.001`](https://attack.mitre.org/techniques/T1078/001/), [`T1078.003`](https://attack.mitre.org/techniques/T1078/003/) |
| Event types | `exec` |

### Description

Detects attempts to enable the root account via "dsenableroot"

### Known false-positive sources

- Unknown

## proc_creation_macos_file_and_directory_discovery

**File and Directory Discovery - MacOS**  
File and Directory Discovery - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_file_and_directory_discovery` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniil Yugoslavskiy, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1083`](https://attack.mitre.org/techniques/T1083/) |
| Event types | `exec` |

### Description

Detects usage of system utilities to discover files and directories

### Known false-positive sources

- Legitimate activities

## proc_creation_macos_find_cred_in_files

**Credentials In Files**  
Credentials In Files

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_find_cred_in_files` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Igor Fits, Mikhail Larin, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/) |
| Event types | `exec` |

### Description

Detecting attempts to extract passwords with grep and laZagne

### Known false-positive sources

- Unknown

## proc_creation_macos_gui_input_capture

**GUI Input Capture - macOS**  
GUI Input Capture - macOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_gui_input_capture` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by remotephone, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1056.002`](https://attack.mitre.org/techniques/T1056/002/) |
| Event types | `exec` |

### Description

Detects attempts to use system dialog prompts to capture user credentials

### Known false-positive sources

- Legitimate administration tools and activities

## proc_creation_macos_hdiutil_create

**Disk Image Creation Via Hdiutil - MacOS**  
Disk Image Creation Via Hdiutil - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_hdiutil_create` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Omar Khaled (@beacon_exe) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| Event types | `exec` |

### Description

Detects the execution of the hdiutil utility in order to create a disk image.

### Known false-positive sources

- Legitimate usage of hdiutil by administrators and users.

## proc_creation_macos_hdiutil_mount

**Disk Image Mounting Via Hdiutil - MacOS**  
Disk Image Mounting Via Hdiutil - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_hdiutil_mount` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Omar Khaled (@beacon_exe) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1566.001`](https://attack.mitre.org/techniques/T1566/001/), [`T1560.001`](https://attack.mitre.org/techniques/T1560/001/) |
| Event types | `exec` |

### Description

Detects the execution of the hdiutil utility in order to mount disk images.

### Known false-positive sources

- Legitimate usage of hdiutil by administrators and users.

## proc_creation_macos_installer_susp_child_process

**Suspicious Installer Package Child Process**  
Suspicious Installer Package Child Process

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_installer_susp_child_process` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059`](https://attack.mitre.org/techniques/T1059/), [`T1059.007`](https://attack.mitre.org/techniques/T1059/007/), [`T1071`](https://attack.mitre.org/techniques/T1071/), [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/) |
| Event types | `exec` |

### Description

Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters

### Known false-positive sources

- Legitimate software uses the scripts (preinstall, postinstall)

## proc_creation_macos_ioreg_discovery

**System Information Discovery Using Ioreg**  
System Information Discovery Using Ioreg

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_ioreg_discovery` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Joseliyo Sanchez, @Joseliyo_Jstnk |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1082`](https://attack.mitre.org/techniques/T1082/) |
| Event types | `exec` |

### Description

Detects the use of "ioreg" which will show I/O Kit registry information.
This process is used for system information discovery.
It has been observed in-the-wild by calling this process directly or using bash and grep to look for specific strings.


### Known false-positive sources

- Legitimate administrative activities

## proc_creation_macos_jamf_susp_child

**JAMF MDM Potential Suspicious Child Process**  
JAMF MDM Potential Suspicious Child Process

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_jamf_susp_child` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Nasreddine Bencherchali (Nextron Systems) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| Event types | `exec` |

### Description

Detects potential suspicious child processes of "jamf". Could be a sign of potential abuse of Jamf as a C2 server as seen by Typhon MythicAgent.

### Known false-positive sources

- Legitimate execution of custom scripts or commands by Jamf administrators. Apply additional filters accordingly

## proc_creation_macos_jamf_usage

**JAMF MDM Execution**  
JAMF MDM Execution

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_jamf_usage` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Jay Pandit |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| Event types | `exec` |

### Description

Detects execution of the "jamf" binary to create user accounts and run commands. For example, the binary can be abused by attackers on the system in order to bypass security controls or remove application control polices.


### Known false-positive sources

- Legitimate use of the JAMF CLI tool by IT support and administrators

## proc_creation_macos_jxa_in_memory_execution

**JXA In-memory Execution Via OSAScript**  
JXA In-memory Execution Via OSAScript

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_jxa_in_memory_execution` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/), [`T1059.007`](https://attack.mitre.org/techniques/T1059/007/) |
| Event types | `exec` |

### Description

Detects possible malicious execution of JXA in-memory via OSAScript

### Known false-positive sources

- Unknown

## proc_creation_macos_launchctl_execution

**Launch Agent/Daemon Execution Via Launchctl**  
Launch Agent/Daemon Execution Via Launchctl

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_launchctl_execution` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Pratinav Chandra |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1569.001`](https://attack.mitre.org/techniques/T1569/001/), [`T1543.001`](https://attack.mitre.org/techniques/T1543/001/), [`T1543.004`](https://attack.mitre.org/techniques/T1543/004/) |
| Event types | `exec` |

### Description

Detects the execution of programs as Launch Agents or Launch Daemons using launchctl on macOS.

### Known false-positive sources

- Legitimate administration activities is expected to trigger false positives. Investigate the command line being passed to determine if the service or launch agent are suspicious.

## proc_creation_macos_local_account

**Local System Accounts Discovery - MacOs**  
Local System Accounts Discovery - MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_local_account` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1087.001`](https://attack.mitre.org/techniques/T1087/001/) |
| Event types | `exec` |

### Description

Detects enumeration of local system accounts on MacOS systems.
This can be used by attackers to identify accounts for lateral movement or privilege escalation.


### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_local_groups

**Local Groups Discovery - MacOs**  
Local Groups Discovery - MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_local_groups` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Ömer Günal, Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1069.001`](https://attack.mitre.org/techniques/T1069/001/) |
| Event types | `exec` |

### Description

Detects enumeration of local system groups

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_network_service_scanning

**MacOS Network Service Scanning**  
MacOS Network Service Scanning

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_network_service_scanning` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1046`](https://attack.mitre.org/techniques/T1046/) |
| Event types | `exec` |

### Description

Detects enumeration of local or remote network services.

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_network_sniffing

**Network Sniffing - MacOs**  
Network Sniffing - MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_network_sniffing` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1040`](https://attack.mitre.org/techniques/T1040/) |
| Event types | `exec` |

### Description

Detects the usage of tooling to sniff network traffic.
An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.


### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_nscurl_usage

**File Download Via Nscurl - MacOS**  
File Download Via Nscurl - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_nscurl_usage` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniel Cortez |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1105`](https://attack.mitre.org/techniques/T1105/) |
| Event types | `exec` |

### Description

Detects the execution of the nscurl utility in order to download files.

### Known false-positive sources

- Legitimate usage of nscurl by administrators and users.

## proc_creation_macos_office_susp_child_processes

**Suspicious Microsoft Office Child Process - MacOS**  
Suspicious Microsoft Office Child Process - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_office_susp_child_processes` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/), [`T1137.002`](https://attack.mitre.org/techniques/T1137/002/), [`T1204.002`](https://attack.mitre.org/techniques/T1204/002/) |
| Event types | `exec` |

### Description

Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution

### Known false-positive sources

- Unknown

## proc_creation_macos_osacompile_runonly_execution

**OSACompile Run-Only Execution**  
OSACompile Run-Only Execution

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_osacompile_runonly_execution` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/) |
| Event types | `exec` |

### Description

Detects potential suspicious run-only executions compiled using OSACompile

### Known false-positive sources

- Unknown

## proc_creation_macos_payload_decoded_and_decrypted

**Payload Decoded and Decrypted via Built-in Utilities**  
Payload Decoded and Decrypted via Built-in Utilities

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_payload_decoded_and_decrypted` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Tim Rauch (rule), Elastic (idea) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059`](https://attack.mitre.org/techniques/T1059/), [`T1204`](https://attack.mitre.org/techniques/T1204/), [`T1140`](https://attack.mitre.org/techniques/T1140/) |
| Event types | `exec` |

### Description

Detects when a built-in utility is used to decode and decrypt a payload after a macOS disk image (DMG) is executed. Malware authors may attempt to evade detection and trick users into executing malicious code by encoding and encrypting their payload and placing it in a disk image file. This behavior is consistent with adware or malware families such as Bundlore and Shlayer.

### Known false-positive sources

- Unknown

## proc_creation_macos_persistence_via_plistbuddy

**Potential Persistence Via PlistBuddy**  
Potential Persistence Via PlistBuddy

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_persistence_via_plistbuddy` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1543.001`](https://attack.mitre.org/techniques/T1543/001/), [`T1543.004`](https://attack.mitre.org/techniques/T1543/004/) |
| Event types | `exec` |

### Description

Detects potential persistence activity using LaunchAgents or LaunchDaemons via the PlistBuddy utility

### Known false-positive sources

- Unknown

## proc_creation_macos_remote_access_tools_meshagent_arguments

**Remote Access Tool - Potential MeshAgent Execution - MacOS**  
Remote Access Tool - Potential MeshAgent Execution - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_remote_access_tools_meshagent_arguments` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Norbert Jaśniewicz (AlphaSOC) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1219.002`](https://attack.mitre.org/techniques/T1219/002/) |
| Event types | `exec` |

### Description

Detects potential execution of MeshAgent which is a tool used for remote access.
Historical data shows that threat actors rename MeshAgent binary to evade detection.
Matching command lines with the '--meshServiceName' argument can indicate that the MeshAgent is being used for remote access.


### Known false-positive sources

- Environments that legitimately use MeshAgent

## proc_creation_macos_remote_access_tools_teamviewer_incoming_connection

**Remote Access Tool - Team Viewer Session Started On MacOS Host**  
Remote Access Tool - Team Viewer Session Started On MacOS Host

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_remote_access_tools_teamviewer_incoming_connection` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Josh Nickels, Qi Nan |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1133`](https://attack.mitre.org/techniques/T1133/) |
| Event types | `exec` |

### Description

Detects the command line executed when TeamViewer starts a session started by a remote host.
Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.


### Known false-positive sources

- Legitimate usage of TeamViewer

## proc_creation_macos_remote_system_discovery

**Macos Remote System Discovery**  
Macos Remote System Discovery

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_remote_system_discovery` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1018`](https://attack.mitre.org/techniques/T1018/) |
| Event types | `exec` |

### Description

Detects the enumeration of other remote systems.

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_schedule_task_job_cron

**Scheduled Cron Task/Job - MacOs**  
Scheduled Cron Task/Job - MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_schedule_task_job_cron` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Alejandro Ortuno, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1053.003`](https://attack.mitre.org/techniques/T1053/003/) |
| Event types | `exec` |

### Description

Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder.

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_screencapture

**Screen Capture - macOS**  
Screen Capture - macOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_screencapture` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by remotephone, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1113`](https://attack.mitre.org/techniques/T1113/) |
| Event types | `exec` |

### Description

Detects attempts to use screencapture to collect macOS screenshots

### Known false-positive sources

- Legitimate user activity taking screenshots

## proc_creation_macos_security_software_discovery

**Security Software Discovery - MacOs**  
Security Software Discovery - MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_security_software_discovery` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniil Yugoslavskiy, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1518.001`](https://attack.mitre.org/techniques/T1518/001/) |
| Event types | `exec` |

### Description

Detects usage of system utilities (only grep for now) to discover security software discovery

### Known false-positive sources

- Legitimate activities

## proc_creation_macos_space_after_filename

**Space After Filename - macOS**  
Space After Filename - macOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_space_after_filename` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by remotephone |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1036.006`](https://attack.mitre.org/techniques/T1036/006/) |
| Event types | `exec` |

### Description

Detects attempts to masquerade as legitimate files by adding a space to the end of the filename.

### Known false-positive sources

- Mistyped commands or legitimate binaries named to match the pattern

## proc_creation_macos_split_file_into_pieces

**Split A File Into Pieces**  
Split A File Into Pieces

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_split_file_into_pieces` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Igor Fits, Mikhail Larin, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1030`](https://attack.mitre.org/techniques/T1030/) |
| Event types | `exec` |

### Description

Detection use of the command "split" to split files into parts and possible transfer.

### Known false-positive sources

- Legitimate administrative activity

## proc_creation_macos_susp_browser_child_process

**Suspicious Browser Child Process - MacOS**  
Suspicious Browser Child Process - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_susp_browser_child_process` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1189`](https://attack.mitre.org/techniques/T1189/), [`T1203`](https://attack.mitre.org/techniques/T1203/), [`T1059`](https://attack.mitre.org/techniques/T1059/) |
| Event types | `exec` |

### Description

Detects suspicious child processes spawned from browsers. This could be a result of a potential web browser exploitation.

### Known false-positive sources

- Legitimate browser install, update and recovery scripts

## proc_creation_macos_susp_execution_macos_script_editor

**Suspicious Execution via macOS Script Editor**  
Suspicious Execution via macOS Script Editor

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_susp_execution_macos_script_editor` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Tim Rauch (rule), Elastic (idea) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1566`](https://attack.mitre.org/techniques/T1566/), [`T1566.002`](https://attack.mitre.org/techniques/T1566/002/), [`T1059`](https://attack.mitre.org/techniques/T1059/), [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/), [`T1204`](https://attack.mitre.org/techniques/T1204/), [`T1204.001`](https://attack.mitre.org/techniques/T1204/001/), [`T1553`](https://attack.mitre.org/techniques/T1553/) |
| Event types | `exec` |

### Description

Detects when the macOS Script Editor utility spawns an unusual child process.

### Known false-positive sources

- Unknown

## proc_creation_macos_susp_find_execution

**Potential Discovery Activity Using Find - MacOS**  
Potential Discovery Activity Using Find - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_susp_find_execution` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Nasreddine Bencherchali (Nextron Systems) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1083`](https://attack.mitre.org/techniques/T1083/) |
| Event types | `exec` |

### Description

Detects usage of "find" binary in a suspicious manner to perform discovery

### Known false-positive sources

- Unknown

## proc_creation_macos_susp_histfile_operations

**Suspicious History File Operations**  
Suspicious History File Operations

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_susp_histfile_operations` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Mikhail Larin, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1552.003`](https://attack.mitre.org/techniques/T1552/003/) |
| Event types | `exec` |

### Description

Detects commandline operations on shell history files

### Known false-positive sources

- Legitimate administrative activity
- Legitimate software, cleaning hist file

## proc_creation_macos_susp_in_memory_download_and_compile

**Potential In-Memory Download And Compile Of Payloads**  
Potential In-Memory Download And Compile Of Payloads

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_susp_in_memory_download_and_compile` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r), Red Canary (idea) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059.007`](https://attack.mitre.org/techniques/T1059/007/), [`T1105`](https://attack.mitre.org/techniques/T1105/) |
| Event types | `exec` |

### Description

Detects potential in-memory downloading and compiling of applets using curl and osacompile as seen used by XCSSET malware

### Known false-positive sources

- Unknown

## proc_creation_macos_susp_macos_firmware_activity

**Suspicious MacOS Firmware Activity**  
Suspicious MacOS Firmware Activity

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_susp_macos_firmware_activity` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Austin Songer @austinsonger |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| Event types | `exec` |

### Description

Detects when a user manipulates with Firmward Password on MacOS. NOTE - this command has been disabled on silicon-based apple computers.

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_susp_system_network_discovery

**System Network Discovery - macOS**  
System Network Discovery - macOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_susp_system_network_discovery` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by remotephone, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1016`](https://attack.mitre.org/techniques/T1016/) |
| Event types | `exec` |

### Description

Detects enumeration of local network configuration

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_suspicious_applet_behaviour

**Osacompile Execution By Potentially Suspicious Applet/Osascript**  
Osacompile Execution By Potentially Suspicious Applet/Osascript

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_suspicious_applet_behaviour` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r), Red Canary (Idea) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1059.002`](https://attack.mitre.org/techniques/T1059/002/) |
| Event types | `exec` |

### Description

Detects potential suspicious applet or osascript executing "osacompile".

### Known false-positive sources

- Unknown

## proc_creation_macos_swvers_discovery

**System Information Discovery Using sw_vers**  
System Information Discovery Using sw_vers

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_swvers_discovery` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Joseliyo Sanchez, @Joseliyo_Jstnk |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1082`](https://attack.mitre.org/techniques/T1082/) |
| Event types | `exec` |

### Description

Detects the use of "sw_vers" for system information discovery

### Known false-positive sources

- Legitimate administrative activities

## proc_creation_macos_sysadminctl_add_user_to_admin_group

**User Added To Admin Group Via Sysadminctl**  
User Added To Admin Group Via Sysadminctl

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_sysadminctl_add_user_to_admin_group` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1078.003`](https://attack.mitre.org/techniques/T1078/003/) |
| Event types | `exec` |

### Description

Detects attempts to create and add an account to the admin group via "sysadminctl"

### Known false-positive sources

- Legitimate administration activities

## proc_creation_macos_sysadminctl_enable_guest_account

**Guest Account Enabled Via Sysadminctl**  
Guest Account Enabled Via Sysadminctl

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_sysadminctl_enable_guest_account` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Sohan G (D4rkCiph3r) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1078`](https://attack.mitre.org/techniques/T1078/), [`T1078.001`](https://attack.mitre.org/techniques/T1078/001/) |
| Event types | `exec` |

### Description

Detects attempts to enable the guest account using the sysadminctl utility

### Known false-positive sources

- Unknown

## proc_creation_macos_sysctl_discovery

**System Information Discovery Via Sysctl - MacOS**  
System Information Discovery Via Sysctl - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_sysctl_discovery` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Pratinav Chandra |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1497.001`](https://attack.mitre.org/techniques/T1497/001/), [`T1082`](https://attack.mitre.org/techniques/T1082/) |
| Event types | `exec` |

### Description

Detects the execution of "sysctl" with specific arguments that have been used by threat actors and malware. It provides system hardware information.
This process is primarily used to detect and avoid virtualization and analysis environments.


### Known false-positive sources

- Legitimate administrative activities

## proc_creation_macos_system_network_connections_discovery

**System Network Connections Discovery - MacOs**  
System Network Connections Discovery - MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_system_network_connections_discovery` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniil Yugoslavskiy, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1049`](https://attack.mitre.org/techniques/T1049/) |
| Event types | `exec` |

### Description

Detects usage of system utilities to discover system network connections

### Known false-positive sources

- Legitimate activities

## proc_creation_macos_system_profiler_discovery

**System Information Discovery Using System_Profiler**  
System Information Discovery Using System_Profiler

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_system_profiler_discovery` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Stephen Lincoln `@slincoln_aiq` (AttackIQ) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1082`](https://attack.mitre.org/techniques/T1082/), [`T1497.001`](https://attack.mitre.org/techniques/T1497/001/) |
| Event types | `exec` |

### Description

Detects the execution of "system_profiler" with specific "Data Types" that have been seen being used by threat actors and malware. It provides system hardware and software configuration information.
This process is primarily used for system information discovery. However, "system_profiler" can also be used to determine if virtualization software is being run for defense evasion purposes.


### Known false-positive sources

- Legitimate administrative activities

## proc_creation_macos_system_shutdown_reboot

**System Shutdown/Reboot - MacOs**  
System Shutdown/Reboot - MacOs

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_system_shutdown_reboot` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Igor Fits, Mikhail Larin, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1529`](https://attack.mitre.org/techniques/T1529/) |
| Event types | `exec` |

### Description

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.

### Known false-positive sources

- Legitimate administrative activity

## proc_creation_macos_tail_base64_decode_from_image

**Potential Base64 Decoded From Images**  
Potential Base64 Decoded From Images

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_tail_base64_decode_from_image` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Joseliyo Sanchez, @Joseliyo_Jstnk |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1140`](https://attack.mitre.org/techniques/T1140/) |
| Event types | `exec` |

### Description

Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner.


### Known false-positive sources

- Unknown

## proc_creation_macos_tmutil_delete_backup

**Time Machine Backup Deletion Attempt Via Tmutil - MacOS**  
Time Machine Backup Deletion Attempt Via Tmutil - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_tmutil_delete_backup` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Pratinav Chandra |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1490`](https://attack.mitre.org/techniques/T1490/) |
| Event types | `exec` |

### Description

Detects deletion attempts of MacOS Time Machine backups via the native backup utility "tmutil".
An adversary may perform this action before launching a ransonware attack to prevent the victim from restoring their files.


### Known false-positive sources

- Legitimate activities

## proc_creation_macos_tmutil_disable_backup

**Time Machine Backup Disabled Via Tmutil - MacOS**  
Time Machine Backup Disabled Via Tmutil - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_tmutil_disable_backup` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Pratinav Chandra |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1490`](https://attack.mitre.org/techniques/T1490/) |
| Event types | `exec` |

### Description

Detects disabling of Time Machine (Apple's automated backup utility software) via the native macOS backup utility "tmutil".
An attacker can use this to prevent backups from occurring.


### Known false-positive sources

- Legitimate administrator activity

## proc_creation_macos_tmutil_exclude_file_from_backup

**New File Exclusion Added To Time Machine Via Tmutil - MacOS**  
New File Exclusion Added To Time Machine Via Tmutil - MacOS

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_tmutil_exclude_file_from_backup` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Pratinav Chandra |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1490`](https://attack.mitre.org/techniques/T1490/) |
| Event types | `exec` |

### Description

Detects the addition of a new file or path exclusion to MacOS Time Machine via the "tmutil" utility.
An adversary could exclude a path from Time Machine backups to prevent certain files from being backed up.


### Known false-positive sources

- Legitimate administrator activity

## proc_creation_macos_wizardupdate_malware_infection

**Potential WizardUpdate Malware Infection**  
Potential WizardUpdate Malware Infection

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_wizardupdate_malware_infection` |
| Severity | `high` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Tim Rauch (rule), Elastic (idea) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| Event types | `exec` |

### Description

Detects the execution traces of the WizardUpdate malware. WizardUpdate is a macOS trojan that attempts to infiltrate macOS machines to steal data and it is associated with other types of malicious payloads, increasing the chances of multiple infections on a device.

### Known false-positive sources

- Unknown

## proc_creation_macos_xattr_gatekeeper_bypass

**Gatekeeper Bypass via Xattr**  
Gatekeeper Bypass via Xattr

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_xattr_gatekeeper_bypass` |
| Severity | `low` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Daniil Yugoslavskiy, oscd.community |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| ATT&CK | [`T1553.001`](https://attack.mitre.org/techniques/T1553/001/) |
| Event types | `exec` |

### Description

Detects macOS Gatekeeper bypass via xattr utility

### Known false-positive sources

- Legitimate activities

## proc_creation_macos_xcsset_malware_infection

**Potential XCSSET Malware Infection**  
Potential XCSSET Malware Infection

| | |
| --- | --- |
| Rule ID | `proc_creation_macos_xcsset_malware_infection` |
| Severity | `medium` |
| Default mode | `monitor` |
| Source | SigmaHQ, by Tim Rauch (rule), Elastic (idea) |
| | This rule records what it would have fired on and raises **no alert** until an operator promotes it. |
| Event types | `exec` |

### Description

Identifies the execution traces of the XCSSET malware. XCSSET is a macOS trojan that primarily spreads via Xcode projects and maliciously modifies applications. Infected users are also vulnerable to having their credentials, accounts, and other vital data stolen.

### Known false-positive sources

- Unknown

