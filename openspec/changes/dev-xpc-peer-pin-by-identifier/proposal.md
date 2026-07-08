# Pin the dev XPC peer by identifier, not a committed cdhash

## Why

The security and network extensions pin inbound XPC peers against a code-signing requirement. The debug path accepted a hardcoded, committed ad-hoc code-directory hash of the locally-built agent (`XPCEventServer.swift`, `adHocCDHashDebug`). A `go build` on arm64 macOS ad-hoc-signs the agent with a content-derived cdhash, so that constant went stale on every meaningful agent rebuild. When stale, the debug extension rejects the agent's XPC hello and silently drops every captured event, taking the whole dev telemetry pipeline (extension to agent to server to ClickHouse) dark while the server, ingest, and ClickHouse all look healthy (observed on edr-dev 2026-07-06, issue #623). Re-pinning meant editing the constant, rebuilding + ad-hoc re-signing the extension, swapping the on-VM binary, and rebooting, and because the pin is a committed constant, reverting it to keep the repo clean reintroduced the breakage on the next build.

## What changes

- **The dev agent gets a stable code-signing identifier.** `task build:agent` re-signs the ad-hoc binary with `--identifier fleet-edr-agent` (a darwin-only step), the same designated identifier the notarized release carries. The identifier is fixed, so it no longer changes on every rebuild the way the linker's default identifier (`a.out`) and the content-derived cdhash did.
- **The debug peer requirement pins that identifier instead of a cdhash.** `XPCEventServer.debug` becomes `(<production team-ID clause>) or identifier "fleet-edr-agent"`. A dev agent rebuild no longer requires editing or redeploying the extension. On a SIP-disabled dev VM this accepts an ad-hoc binary claiming the agent identifier, which realises the identifier-pinning tightening ADR-0007 anticipated for this path.
- **Production peer validation is unchanged.** The active requirement still selects the production string (Apple anchor + team ID, no identifier or cdhash clause) via `#if DEBUG`, so release builds are team-ID-only even if the debug string is left in source.

### Not in this change

- Tightening the production requirement to also pin the agent identifier (the deferred ADR-0007 item). Production stays anchor + team-ID only.
- Any change to the network extension's separate signing or to the agent's release signing path in `packaging/pkg/build.sh`.

## Acceptance

- A dev agent rebuild no longer requires editing and redeploying the extension for XPC to keep working.
- The strict production peer requirement (Apple anchor + FDM team ID) is unchanged for release builds.
- `XPCEventServer` unit tests still assert the production requirement language, and cover the identifier-based debug acceptance.
