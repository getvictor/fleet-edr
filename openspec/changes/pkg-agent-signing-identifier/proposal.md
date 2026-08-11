# Pin the packaged agent's code-signing identifier

## Why

`packaging/pkg/build.sh` signed the agent without `--identifier`, leaving the value to codesign's default. For a bare Mach-O signed ad-hoc that default is `fleet-edr-agent-<hash>`, not `fleet-edr-agent`.

The system extension's debug XPC peer requirement pins the bare `fleet-edr-agent` (`XPCEventServer.agentIdentifierDebug`). So every dry-run package installed an agent the extension then refused to talk to: the agent connects to nothing, health reports `never_connected`, and the host silently produces no telemetry. Measured on edr-dev, where a dry-run pkg install took a working host to `unhealthy / never_connected` until the agent binary was replaced by hand.

That path is exactly what the dry-run exists for. It is how a developer or a QA host gets a package without release secrets, and the packages it produced could not talk to the extension they shipped alongside.

The release path is unaffected in practice, because the production peer requirement matches on the Apple anchor and team ID rather than the identifier. But `XPCEventServer` documents the notarized release as carrying `fleet-edr-agent` as its designated identifier, and nothing enforced that: it held only because codesign's default happened to produce it.

## What changes

- **The packaged agent is signed with an explicit `--identifier fleet-edr-agent`**, in both the dry-run and release paths. This matches what `task build:agent` already does for locally-built agents, and makes the value the extension pins a stated contract rather than a side effect of a tool default.
- **The build asserts what it actually produced.** Passing the flag is not the same as verifying the result, and a wrong identifier is invisible at build time: it surfaces only on an endpoint, as an agent that installs, connects to nothing and reports never-connected. The build now reads the identifier back with `codesign -dvv` and fails the build if it is not the expected value. The assertion runs on both paths, so the dry-run job enforces it for ad-hoc signing and a real tag enforces it for Developer ID signing.

## What this deliberately does not do

- It does not change the production requirement to match on identifier. Anchor plus team ID is the stronger check, and adding an identifier clause would only narrow it for no security gain.
