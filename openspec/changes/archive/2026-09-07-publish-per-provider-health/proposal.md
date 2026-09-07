# Publish per-provider capture health to the server

## Why

The extension already tracks each capture provider separately, and the agent already consumes that map: `ProviderLiveness` reports it, `GradeProviders` grades it, and the self-heal controller remediates from it. But the agent collapses it into a single `network_extension` component before posting, so the map never reaches the server. Provider names survive only inside a human message, and only when something is already stopped.

That gap forced a workaround in #677, which detects a provider that wedges while reporting itself healthy. Unable to read a per-provider claim, it infers one: it treats "this stream produced events in the last 7 days" as evidence the provider is in use. That proxy is inaccurate in two bounded ways, both documented in the shipped code:

- A provider deliberately disabled **during** that window is reported as degraded until its last events age out, because historical activity cannot distinguish "stopped on purpose yesterday" from "wedged yesterday".
- A wedge lasting longer than the window stops being reported, because the window empties too.

Both disappear once the server can read the provider's own claim.

## What changes

The agent reports each provider the extension tells it about as its own component, alongside the existing one for the extension. This is additive: the collapsed component is unchanged, so every existing consumer (the Hosts-list badge, the rollup, the health detail) keeps working, and an older agent that reports only the collapsed component stays valid.

## The design decision that matters

Provider components are rendered from the LATEST liveness report rather than accumulated as registered components.

Accumulating is the obvious implementation and is wrong here. A provider an operator deliberately switches off is reported by the extension as ABSENT, not as stopped, so an accumulated component would keep asserting "running" for a provider that is off. A stale positive claim is worse than silence, precisely because the server's job is to contradict these claims against arriving telemetry: it would report a wedge on a provider nobody is running on purpose, which is the false positive this whole change exists to remove.

## Impact

- Affected specs: `agent-status-reporting`
- Affected code: `agent/health`, `ui/src/components/HostHeader.tsx`
- No server change is required to accept this: the component vocabulary is open by contract and the server stores unrecognised types verbatim.
- This is the producer half of #702. The consumer half is a follow-up that gates the derived check on each provider's own claim and deletes the reference window and both limitations above.
