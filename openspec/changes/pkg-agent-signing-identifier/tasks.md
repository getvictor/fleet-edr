# Pin the packaged agent's code-signing identifier: tasks

## 1. Fix

- [x] `packaging/pkg/build.sh`: pass `--identifier "$AGENT_SIGNING_IDENTIFIER"` when signing the agent, matching what `task build:agent` already does. Applies to both paths: the dry-run needs it to be usable at all, and the release path gets a stated identifier instead of one that happens to fall out of codesign's default.
- [x] `packaging/pkg/build.sh`: read the identifier back with `codesign -dvv` after signing and fail the build if it is not the expected value. Passing the flag is not the same as verifying the result, and this is the difference between the spec being documentation and being enforced: the assertion runs on both paths, so the dry-run CI job checks the ad-hoc mode and a real tag checks the Developer ID mode. It carries the scenario markers, because it is the code that actually enforces them.

## 2. Spec

- [x] `release-packaging` delta: ADDED "The packaged agent carries the code-signing identifier the extension expects".

## 3. Verification

- [x] Rebuilt the pkg via `packaging/pkg/build.sh <tag> --dry-run`; the staged binary now reports `Identifier=fleet-edr-agent` where it previously reported `fleet-edr-agent-55554944bf9af99f050b30defb13aa639a07baf8`, and the new assertion passes.
- [x] Checked the assertion actually catches the regression rather than only passing: signing the same binary WITHOUT `--identifier` yields `agent-wrongid-55554944199156cd6ff53f65ffb04bacdbc0a936`, which the comparison rejects. A guard that has only ever been observed passing is not evidence it can fail.
- [x] Installed the rebuilt pkg on edr-dev (macOS 26.3). The agent it installs now establishes both extension sessions (`receiver connected` for the security extension and for `group.com.fleetdm.edr.networkextension`) and the `network_extension` component reports `healthy / activated`. Before the fix, the same install path left the host at `unhealthy / never_connected` until the agent binary was replaced by hand.

## 4. Not covered

- [ ] The release path's identifier is asserted by construction rather than observed, since a real Developer ID signature needs release secrets. The dry-run path is what the change was measured against.
