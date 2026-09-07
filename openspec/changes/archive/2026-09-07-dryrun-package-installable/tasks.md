# Make the dry-run package one that can actually be installed: tasks

## 1. Entitlements in every build mode

- [x] `packaging/pkg/build.sh`: the entitlements re-sign moves out of the release branch and runs in both modes. The provisioning-profile embed stays release-only, because profiles are issued per signing identity and are enforced only where SIP is on, which is exactly the host a dry-run package is not for.
- [x] The bundle-existence checks (sysext, NE) move to the shared path with them. A staged app missing an extension produces a package that installs and then does nothing, which is worth failing over however the app was built.
- [x] Corrected the comment that said the entitlement plists are "the ones the Xcode targets reference". The project sets no `CODE_SIGN_ENTITLEMENTS` at all, so this step is not preserving anything; it is the only place the entitlements are applied, which is what makes skipping it in one mode so damaging.

## 2. Assert what was applied

- [x] Read the entitlements back off each of the three bundles and fail (exit 17) naming the bundle and the missing key. The step it guards was silently skipped in one mode for months and its absence surfaces only when somebody installs the package and watches activation fail with a reason the platform redacts by default.
- [x] Mutation-checked: pointing the app's entitlements at an empty plist fails the build with `the host app is signed without com.apple.developer.system-extension.install`, rather than producing a package that installs and cannot activate.

## 3. A test package replaces what is installed

- [x] `BundleIsVersionChecked` is `true` on release and `false` on a dry run. A dry-run package carries the local Debug build's fixed `1.1/1`, so under version-checking it skipped the app while still replacing the agent and reported success, leaving a new agent running against the old app and extensions.

## 4. Verification

- [x] `task pkg:dryrun`, then read the entitlements off all three staged bundles: host app carries `system-extension.install` and `networking.networkextension`, security extension carries `endpoint-security.client`, network extension carries `networking.networkextension`. Before this change all three carried `get-task-allow` alone.
- [x] Installed on edr-dev (SIP off), which is the first end-to-end pkg upgrade observed on this project; two earlier attempts recorded on #684 never got past activation. Both extensions reached `activated enabled` at `1.1/28` automatically through the postinstall's activation LaunchAgent, `edr activate` reported `activate completed` for both in about 300ms (readable rather than `<private>`, since the package now ships the #688 build), both providers came back running with no re-consent prompt, the agent reconnected over XPC to both extensions signed `fleet-edr-agent`, and server-side host health returned to `healthy`.
- [x] Installed again with a package whose app version was LOWER than the installed one, and the app was still replaced: the version-check change verified by behaviour rather than by reading `PackageInfo`, whose encoding of the flag is not what it appears to be.
- [x] `shellcheck`; `openspec validate --strict`; `spectrace check --strict`.

## 5. Not covered

- [ ] A SIP-enabled host. A dry-run package carries no provisioning profile, so its restricted entitlements are not honoured there. This is Apple's signing model, not something the script can work around, and the release path remains the only thing valid on a pilot Mac.
- [ ] The released package itself was not rebuilt: that needs Developer ID credentials and a tag. The change to the release path is limited to where the shared block sits, and the release path's signing arguments are unchanged.
