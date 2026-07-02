## Why

Analysts convict on command lines and code-signing evidence (epic #577's research: the command line, not the process name, is what distinguishes benign from malicious, and on macOS the signer category is the equivalent of Windows signer reputation). Today walking an ancestry chain costs a click plus a panel scan per node, the panel renders only the raw `signing_id`, team id and signing flags are fetched but never shown, and nothing is copyable in one click. This is story #580, wave 1 of the epic.

## What Changes

- Hovering a process node shows a tooltip with the full command line and a derived code-signing verdict, so an ancestry chain reads without clicks. Aggregated (`×N`) nodes show the group size and their representative's command line.
- A signing verdict is derived client-side from the fields the tree already carries: "Apple platform", "Developer ID (Team <id>)", "ad-hoc" (`flags & CS_ADHOC`), "signed" (residual), or "unsigned" (no code-signing block, matching the extension's contract of omitting the block when both identifiers are absent).
- Ad-hoc and unsigned nodes get a subtle amber marker in the graph, a triage cue alongside the existing red alert styling.
- The detail panel replaces the raw `signing_id (platform)` line with the verdict badge plus the signing id and team id, and gains one-click copy for the command line, path, SHA-256, cdhash, signing id, and team id.
- The UI `Process` type gains the `cdhash` field the server already sends.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `web-ui`: ADDED requirement "Process node conviction evidence" (hover tooltip, signing verdict, unsigned marker); MODIFIED requirement "Process detail content" (verdict + team id + cdhash + copy affordances). The tree-visualization requirement is deliberately untouched to avoid colliding with the in-flight `server-sibling-aggregation` delta that already modifies it.

## Impact

- UI only: new `ui/src/signing.ts` (verdict derivation + CS_ADHOC constant), `ui/src/types.ts` (cdhash), `ui/src/components/ProcessDetail.tsx` (verdict badge + copy buttons), `ui/src/components/ProcessTree.tsx` (hover tooltip + node marker), styles, and co-located tests.
- No server, agent, wire, or schema changes: `ProcessNode` embeds `Process`, so tree nodes already carry `code_signing`, `sha256`, and `cdhash`.
