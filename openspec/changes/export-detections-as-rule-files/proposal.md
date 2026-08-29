# Export detections as declarative rule files

## Why

A detection an operator cannot read is a detection they have to trust. Today the only way to learn what a rule matches, what it will not catch, and which evaluator decides it is to read Go, and the generated markdown page describes the rules in prose that no tool can consume.

Exporting each detection as a declarative file makes the catalog inspectable and, for the rules that later become Sigma, portable. It is the first step of the rule-format work and deliberately the safest: pure output that nothing reads back, so a wrong choice costs a serialiser rewrite rather than an engine rewrite.

## What changes

Every registered detection renders as a rule file: standard Sigma metadata (title, id, status, description, author, level, tags, logsource, falsepositives) plus one namespaced `x-engine` key carrying what Sigma has no concept of (our rule id, the rule kind, its portability, the event types it consumes, the evaluator that decides it, the exclusion dimensions it honours, and its known limitations).

The pack is generated into `docs/rules/`, one file per detection, and served per rule at `GET /api/rules/{id}/export`. A rule declares the evaluator that decides it, which is what makes a Go-implemented rule inspectable rather than merely described.

Non-detections are not exported. A projection of an agent-side decision and a health signal about our own agent have no detection logic to inspect, no tuning surface, and no adversary claim, so a rule file for either would misrepresent all three.

## What this deliberately does NOT do

**No rule is exported as Sigma.** A rule is `type: sigma` only when its logic lives in the file's detection block AND the engine evaluates it from there. All ten detections are Go implementations, so every export is honestly `type: graph` / `portable: none`. Emitting a hand-written detection block the engine never reads would assert behaviour that nothing verifies, which is how an early draft of this format acquired an algorithm name that no code implements.

**No rule's parameters are exported.** Rule constants are unexported Go values with no accessor. Adding accessors purely so a serialiser could read them back is work the next change undoes when it moves those values into the files for real.

## Impact

- New generated artifact under `docs/rules/`, refreshed with `task docs:rule-pack` and drift-checked in CI.
- One new read-only endpoint, gated by the same authorization as the rule catalog.
- Nothing about registration, evaluation, tuning, or alerting changes. No rule reads its own file.
