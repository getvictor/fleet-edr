# Lessons and gotchas

Hard-won knowledge from building the Fleet EDR macOS agent. Each item cost
debugging time; this document exists so the next person doesn't pay the same
price.

## macOS system extensions

### sysextd requires the app to be in /Applications

`OSSystemExtensionRequest` fails silently if the host app isn't in
`/Applications/` (or a subfolder) and developer mode is off. The error in
`sysextd` logs is:

```
Failing to realize <bundleID> as the app requesting activation
isn't in the /Applications folder and developer/groundhog mode isn't on
```

Fix: either deploy to `/Applications/` or run
`systemextensionsctl developer on` (requires GUI auth).

### CFBundleIdentifier must be in the host app's Info.plist

With `GENERATE_INFOPLIST_FILE = NO` in the Xcode project, the
`PRODUCT_BUNDLE_IDENTIFIER` build setting is NOT merged into Info.plist
automatically. sysextd rejects the activation with `app_missing_identifier`.
You must add `CFBundleIdentifier`, `CFBundleName`, `CFBundleVersion`,
`CFBundleShortVersionString`, `CFBundlePackageType`, and
`CFBundleExecutable` manually.

### Activation hangs without output if both extensions fail

The host app submits activation requests for both extensions and calls
`dispatchMain()`. If both fail, the `didFailWithError` delegate callback fires
but `exit()` only runs when `pendingCount` reaches zero. If your log subsystem
redacts errors with `<private>`, you see nothing. Check `sysextd` logs with
`log show --predicate 'process == "sysextd"'`.

### Old extensions coexist with new ones

macOS doesn't auto-remove extensions when you change bundle IDs. If you rename
from `com.foo.ext` to `com.bar.ext`, BOTH remain active. The old one keeps
running and consuming ES subscriptions. Toggle off the old extensions in System
Settings or reboot and approve only the new ones.

### stagedCdhashes must be real in db.plist

When manually editing `/Library/SystemExtensions/db.plist` (SIP-disabled dev),
setting `stagedCdhashes` to `$null` causes `nesessionmanager` to fail with
"Cannot create launchd job...the extension does not have the required additional
launchd job entries." Compute real cdhashes with `codesign -dvvv <bundle>`.
Even so, manual db.plist editing is fragile -- prefer
`OSSystemExtensionRequest` from a GUI session.

## XPC communication

### XPC connections are lazy

Creating an `xpc_connection_t` via `xpc_connection_create_mach_service` does
NOT actually connect. The Mach port lookup happens on the first message. Without
a hello/handshake message, the listener never sees the peer.

### Running extension binaries directly does NOT register Mach services

If you `sudo ./extension-binary` instead of going through sysextd/launchd, the
XPC Mach service declared in Info.plist is never registered with launchd. The
extension runs fine, but no external process can connect to it via XPC.

### Hardened runtime required for XPC peer validation

`xpc_connection_set_peer_code_signing_requirement` uses kernel-level runtime
code signing, NOT the static on-disk check. The agent binary MUST be signed
with `--options runtime` (`CS_RUNTIME` flag 0x10000). Without it, the kernel
can't validate code pages at runtime, and the peer check fails even though
`codesign -v -R` (static check) passes.

```bash
# Wrong: peer check will reject
codesign --sign "cert" agent-binary

# Correct: peer check works
codesign --sign "cert" --options runtime agent-binary
```

### ESF vs Network Extension use different Mach service registration

| Extension type | Info.plist key | Registered by |
|---|---|---|
| Endpoint Security | `NSEndpointSecurityMachServiceName` | sysextd |
| Network Extension | `NEMachServiceName` (inside `NetworkExtension` dict) | nesessionmanager |

The generic `MachServices` dict in Info.plist is for LaunchDaemons only.
System extensions must use the type-specific keys above.

### NEMachServiceName is the XPC endpoint for network extensions

The `NEMachServiceName` value (e.g., `group.com.fleetdm.edr.networkextension`)
is registered in the **global Mach bootstrap namespace** by nesessionmanager.
Any unsandboxed process can connect to it. This is how LuLu and other macOS
firewalls handle IPC between the NE system extension and the controlling daemon.
The app-group prefix does NOT restrict connections to group members.

## Network extensions

### nesessionmanager ignores MachServices dict

Unlike sysextd (which reads `NSEndpointSecurityMachServiceName`),
nesessionmanager does NOT read the `MachServices` dict at the top level of the
extension's Info.plist. Only `NEMachServiceName` inside the `NetworkExtension`
dict is registered. Custom entries in `MachServices` are silently ignored.

### Content filter requires proper system extension activation

Running the NE binary via a custom LaunchDaemon registers the Mach service but
does NOT activate the content filter. `nesessionmanager` must launch the
extension for `NEFilterDataProvider.startFilter` to be called and traffic to
flow through `handleNewFlow`.

### NEFilterManager.loadFromPreferences hangs via SSH

`NEFilterManager.shared().loadFromPreferences` talks to `nesessionmanager` via
XPC. When run via SSH (no GUI session), the XPC reply may never arrive. Run
the host app from a GUI Terminal on the VM, or use a configuration profile.

### DNS proxy can break all DNS resolution

`NEDNSProxyProvider` is a full DNS proxy. If your forwarding code fails, ALL
DNS on the endpoint breaks. Safety practices:
- Use `Network.NWConnection` to forward to the original destination (the system
  excludes extension's own connections from the proxy chain)
- Never block or drop datagrams due to parse failures
- Have `disable-dns-proxy` ready before testing
- Keep an SSH session open with the VM IP (not hostname)

## Endpoint Security framework

### es_new_client requires entitlement even with SIP disabled

On macOS 26, `es_new_client` checks the
`com.apple.developer.endpoint-security.client` entitlement even with SIP
disabled. Apply it via `codesign --entitlements`.

### Debug-level os.log messages are not persisted

`os_log` at `.debug` level is NOT written to the log store. Use
`log stream --process <PID> --info --debug` for real-time capture. For
`log show`, add `--debug --info` flags.

### String interpolation in os.log is redacted by default

Path strings and other dynamic values show as `<private>` in log output. Use
`.public` privacy level in development, `.private(mask: .hash)` in production.

## Code signing and certificates

### Team ID is public, not a secret

Team IDs appear in every signed binary. Hardcoding them in peer code signing
requirements and Mach service prefixes is the intended pattern, not a leak.

### Apple Development vs Developer ID

| Certificate | Use case | Provisioning profile needed? |
|---|---|---|
| Apple Development | Dev/test on enrolled devices | Yes (App Store), No (SIP-disabled) |
| Developer ID Application | Distribution outside App Store | No |

For SIP-disabled VMs, Apple Development certs work without provisioning profiles
because AMFI is relaxed. Entitlements embedded via `codesign --entitlements`
are honored directly.

### WWDR intermediate certificate must be in the keychain

Without the Apple Worldwide Developer Relations (WWDR G3) intermediate
certificate in the login keychain, signing identities show as "not valid" in
`security find-identity -v -p codesigning` even though the leaf certificate is
installed. Install it from
`https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer`.

### Creating .p12 files requires -legacy flag

OpenSSL 3.x defaults to a PKCS12 format that macOS Keychain cannot import.
Use `openssl pkcs12 -export -legacy` to create compatible .p12 bundles.

## Build and deployment

### CGo build cache doesn't detect C header changes

When a Go file includes C headers from other directories via `#include`, the
Go build cache doesn't detect changes in those headers. Use `go build -a` to
force a full rebuild after C header modifications.

### Xcode IDESimulatorFoundation plugin can break xcodebuild

If `xcodebuild` fails with "A required plugin failed to load", run
`xcodebuild -runFirstLaunch` to fix it.

### codesign order matters for nested bundles

Sign inner bundles (system extensions) before the outer bundle (host app).
If you modify a nested bundle after signing the outer one, you must re-sign
the outer bundle or `codesign --verify --deep --strict` will fail.

## VM development

### VM IP and bridged networking

The VM uses bridged networking on the host's bridge interface (typically
`bridge100`). The host IP as seen from the VM is the bridge gateway
(e.g., `192.168.64.1`). Use this when pointing the agent at the server.

### profiles install is deprecated on macOS 26

`sudo profiles install -path foo.mobileconfig` no longer works. Profile
installation requires the System Settings GUI. To install via CLI, use
`open /path/to/profile.mobileconfig` and approve in System Settings.

### zsh `status` is a read-only variable

Don't use `status` as a variable name in zsh scripts on the VM. It conflicts
with the built-in `$status` (equivalent to `$?`).

## Detection engine

### Detection failures should not permanently drop events

If `detection.Engine.Evaluate` fails (e.g., MySQL connection timeout during
alert insertion), the events must NOT be marked as processed. The processor
should unclaim the batch so events are retried in the next cycle.

### Network event timestamps can precede process fork times

The network extension may report a `network_connect` event slightly before
the ESF extension reports the corresponding `fork` event (observed ~39ms
delta). The process detail time-range query can miss these. Consider widening
the lower bound by ~100ms when joining network events to processes.
