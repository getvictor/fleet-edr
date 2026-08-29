# Rules read their parameters from the rule pack

## Why

A detection's match lists and thresholds were Go constants, so changing what counts as a shell meant editing source and shipping a binary. The rule files added in #757 described those values in prose but were not the source of them, which meant a file could disagree with the code it claimed to document and nothing would notice.

## What changes

Each rule's parameters move into its file under `x-engine.params`, and the rules read them at boot. Values are validated against a schema registered per **algorithm**, so a parameter the algorithm never reads is refused rather than silently ignored, and two rules sharing an algorithm cannot disagree about what it accepts.

The pack moves from `docs/rules/` to `server/rules/internal/catalog/pack/`, beside the code that reads it. A `go:embed` pattern cannot contain `..`, so the only way to keep the pack in `docs/` was a second generated copy, which is the arrangement that let the embedded OpenAPI spec drift 49 lines from its source.

Values that more than one rule matches against live in `pack/lists.yml` instead of being copied into each consumer's file. Three lists qualify, across seven consumers.

## What stays in code, deliberately

Parameters that feed **retrieval** rather than the decision: the ingest and clock-skew pads, the ancestor-walk and descendant caps, the DNS port. Raising them changes no finding and merely widens a scan; lowering them causes silent false negatives. There is no setting that improves detection, so exposing them would offer a knob whose every position is worse than the default.

## Impact

- No detection data remains hardcoded. Every match list and decision threshold is read from a file.
- A malformed value fails at boot naming the rule, rather than at first fire as a detection that silently did not happen.
- Behaviour is unchanged: every existing rule test passes without modification, which is the contract this step is built on.
- Runtime overrides are **not** included; they change this design rather than extend it, and are tracked separately.
