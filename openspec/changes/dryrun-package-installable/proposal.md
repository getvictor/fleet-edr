# Make the dry-run package one that can actually be installed

## Why

`task pkg:dryrun` produced a package that could never activate anything, and one that silently refused to replace an existing install. Both were invisible because nobody had installed a dry-run package: CI only expands it and checks the layout.

**Entitlements.** The re-sign that applies the shipped entitlements ran on the release path only, so a dry-run package's app and both extensions carried `get-task-allow` alone. An app without `com.apple.developer.system-extension.install` cannot submit an activation request; extensions with no category entitlement are rejected with "does not appear to belong to any extension categories". That is not hypothetical: an identically unentitled app is what made edr-dev look like a corrupt VM for a week, and the reason was only readable after #688 stopped redacting it.

The Xcode project sets no `CODE_SIGN_ENTITLEMENTS` at all (zero occurrences in the project file), so this re-sign is not preserving something the build did. It is the only place the entitlements are ever applied. The comment in the script claimed otherwise.

**Version checking.** The app component ships `BundleIsVersionChecked=true`, which is right for a release. A dry-run package always carries the local Debug build's fixed `1.1/1`, so installing one over an existing install skips the app while still replacing the agent, and reports "The upgrade was successful". Measured on edr-dev: the agent was replaced, the app was not, and the host was left running a new agent against the old app and old extensions.

## What changes

- **The entitlements re-sign runs in both build modes**, with the provisioning-profile embed staying release-only (profiles are issued per signing identity and are only enforced where SIP is on).
- **The build asserts the entitlements it just applied**, reading them back off each of the three bundles and failing with the bundle name and missing key. Same reasoning as the agent-identifier assertion in #686: a load-bearing step that was silently skipped in one mode for months cannot be guarded by a comment.
- **A dry-run package no longer version-checks the app**, so it replaces whatever is installed. The released package keeps version-checking.
- The bundle-existence checks move to the shared path, so a staged app missing an extension fails the build in either mode.

## Evidence

The whole point was to make the dry-run package installable, so it was installed, and this is the first end-to-end pkg upgrade observed on this project (two earlier attempts, recorded on #684, never got past activation).

| step | result |
| --- | --- |
| install over an existing install, higher app version | app replaced, both extensions activated at `1.1/28` automatically via the postinstall LaunchAgent |
| providers after the upgrade | `content_filter` and `dns_proxy` both running, no re-consent prompted |
| agent after the upgrade | XPC reconnected to both extensions, signed `fleet-edr-agent` |
| install over an existing install, LOWER app version | app replaced, which is what the version-check change exists for |

## What this does not do

A dry-run package still cannot be validated on a SIP-enabled host: without an embedded provisioning profile its restricted entitlements are not honoured there, and that is a property of Apple's signing model rather than something the script can work around. The release path remains the only thing valid on a pilot Mac.

The extensions inside a dry-run package carry the local build's version, and the operating system applies its own version rules to system extensions, so replacing the app does not roll the extensions backwards. Testing an upgrade cutover still means bumping the extension version deliberately.
