# Evaluate rules written in the Sigma format

## Why

Every detection is a Go function today, so a rule cannot be read without reading source, and the 3,141-rule upstream SigmaHQ corpus cannot be run at all. #757 made our detections exportable as Sigma files and #758 moved their parameters into those files, but the engine still cannot evaluate a rule written in the format it now emits. This adds that evaluator, which is what #761 converts our expressible rules onto and what #763 imports upstream content through.

## What changes

A new `server/rules/internal/sigma` package compiles a Sigma `detection:` block into an evaluable rule and matches it against a single event. It is a pure evaluator with no engine wiring: binding it to our event payloads and the field taxonomy is #761.

## The subset is measured, not guessed

The scope was settled by counting the corpus rather than by reading the specification, and the count disagrees with this issue's original scope in both directions.

Across the 69 macOS rules, the modifiers used are `contains` (60 rules), `endswith` (58), `all` (22), `re` (2) and `startswith` (1). Nothing else appears. `base64offset` and `cidr`, which #760 listed as required, are used by **zero** macOS rules and by 7 and 21 rules corpus-wide; they are omitted deliberately, and building them now would be the speculative code CLAUDE.md forbids. Two constructs the issue did not mention earned implementation instead: wildcards in plain values, used by 31 of the 69 macOS rules and invisible to a census of modifiers alone, and `null` (match on field absence), used by 73 rules corpus-wide, an order of magnitude more than `base64offset`.

Aggregation and correlation are absent from **all 3,141 corpus rules**, not merely rare on macOS, which is why this evaluator holds no state between events.

Result: all 69 macOS rules compile, and 2,941 of 3,141 corpus-wide (93.6%). The remainder need `windash` (119 occurrences, Windows only), keyword search (87), `cidr` (30) and `fieldref` (8), each of which fails loudly at load.

## Why not bradleyjkemp/sigma-go

Considered and rejected on evidence. Its latest release is v0.6.6 (2024-09-04), pre-1.0 and untouched for about two years. Its `Event` is `interface{}` with reflection-based field access accumulating `[]interface{}` per field, so adopting it means unmarshalling every payload into a `map[string]any` per event per rule, which is the opposite of what this path needs. It adds four build-time dependencies and a second YAML library to the code that decides whether a detection fires, and carries aggregation machinery the census says nothing uses. Against that, the surface we actually need is five modifiers and a small condition grammar.

## Impact

No behaviour change: nothing calls the evaluator yet. The risk this PR carries is confined to what the next one inherits.
