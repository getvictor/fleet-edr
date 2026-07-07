## Context

The wire and server already deliver everything (schema/events.json `code_signing` {team_id, signing_id, flags, is_platform_binary} + sha256 + cdhash; `ProcessNode` embeds `Process`), so this is purely a presentation change. There is no tooltip machinery in the D3 tree today; the detail panel shows `signing_id (platform)` and nothing is copyable. The extension omits the `code_signing` block entirely when both identifiers are absent, which is the "unsigned" signal.

## Goals / Non-goals

**Goals:**

- Conviction evidence readable while walking the tree (hover, no clicks) and copyable in one click from the panel.
- One verdict derivation shared by tooltip, marker, and panel badge.

**Non-goals:**

- No notarization claim: ESF exposes signing flags and identifiers, not a ticket check, so signer category is the honest macOS verdict.
- No server-side `is_unsigned` marking (that belongs to #417's interesting-branches default in epic #415).
- No changes to node selection, aggregation, or the tree layout.

## Decisions

- **Verdict order**: unsigned (no block) -> ad-hoc (`flags & CS_ADHOC`, 0x2, the kernel CS status bit; the constant is introduced with a comment since no CS_* constants exist outside Swift) -> Developer ID when team_id is non-empty -> Apple platform when is_platform_binary -> "signed" residual (identifier present, no team, not platform). Team-id presence is checked before the platform flag because ESF redaction on ad-hoc dev builds reports is_platform_binary=true for everything (#187), while team_id stays trustworthy.
- **Tooltip is a positioned HTML div**, not an SVG `<title>`: the content is styled (monospace command line + verdict badge) and must be testable. The content builder is a pure function so tests cover enrolled, unsigned, and aggregated shapes without simulating D3 hover geometry.
- **Marker is an amber stroke ring** on the node dot (`#ebbc43`, the `$ui-warning` token; D3 uses literal hex like the existing alert red) for ad-hoc and unsigned verdicts, preserving the fill's alerted/exited/running semantics.
- **Aggregated nodes** carry their representative's signing fields; the tooltip labels the group (`×N processes`) and shows the representative's command line and verdict rather than pretending to describe every member.
- **Spec shape**: node evidence is an ADDED requirement, not a MODIFIED "Process tree visualization", because the in-flight `server-sibling-aggregation` change already carries a MODIFIED block for that requirement and two parallel rewrites would collide at archive time.

## Risks / Trade-offs

- [Verdict on aggregated nodes describes the representative] -> the group key includes binary identity (path + signing), so members share the verdict by construction; noted in the tooltip test.
- [Hover on touch devices] -> tooltip is hover-only; the click-through panel remains the full surface, so no capability is hover-exclusive except speed.
