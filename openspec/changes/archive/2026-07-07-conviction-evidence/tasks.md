## 1. Verdict core

- [x] 1.1 `ui/src/signing.ts`: `CS_ADHOC = 0x2` (documented), `deriveSigningVerdict(code_signing?)` returning kind + label in the decision order unsigned -> ad-hoc -> Developer ID (team id) -> Apple platform -> signed; table-driven test covering all five categories (spec marker `verdict-distinguishes-the-signer-categories`)
- [x] 1.2 `ui/src/types.ts`: add `cdhash?: string` to `Process`

## 2. Detail panel

- [x] 2.1 `ProcessDetail.tsx`: replace the raw `signing_id (platform)` line with the verdict badge + signing id + team id rows; add `CopyButton` to command line, path, SHA-256, cdhash (when present), signing id, team id
- [x] 2.2 Component tests: verdict rendering per category, copy buttons present with accessible names (spec markers `process-detail-surfaces-investigation-fields`, `evidence-fields-copy-in-one-click`)

## 3. Tree hover + marker

- [x] 3.1 Pure tooltip-content builder (name, full command line, verdict, aggregated group size) with tests for plain, unsigned, and aggregated nodes (spec markers `hovering-a-node-shows-the-command-line-and-verdict`, `aggregated-node-hover-describes-the-group`)
- [x] 3.2 `ProcessTree.tsx`: positioned tooltip div wired to node mouseenter/mousemove/mouseleave; amber stroke ring (`#ebbc43`) on ad-hoc/unsigned node dots (spec marker `unsigned-and-ad-hoc-nodes-are-marked-in-the-graph`)
- [x] 3.3 Styles for the tooltip (monospace command line, verdict line) in `ProcessTree.scss`

## 4. Verification

- [x] 4.1 `cd ui && npm test`, `npm run lint`, tsc, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 4.2 Manual QA: rebuild UI, restart dev server, hover nodes on a real host tree in Chrome (verdicts, tooltip, marker), verify panel copy buttons

## 5. Docs

- [x] 5.1 CHANGELOG entry under 0.4.0
