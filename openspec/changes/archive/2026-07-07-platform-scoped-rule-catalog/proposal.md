## Why

The detection engine evaluates every registered rule against every event, but all ten catalog rules target macOS tradecraft (launchd, dyld, osascript, Keychain, sudoers). Once a Windows agent starts emitting events (ADR-0018), those macOS rules would fire against Windows events and produce false positives. This change makes each rule declare the platforms it targets and has the engine evaluate a rule only against events whose platform is in that set, closing the cross-platform false-positive gap before Windows telemetry arrives. It builds on the platform-tagged event contract: every event already carries a platform (normalized to darwin for legacy agents), so the engine can scope purely from the event batch with no per-host lookup.

## What changes

- The `Rule` interface gains a required `Platforms()` method, so a rule cannot ship without declaring its target operating systems (compile-enforced, like `Doc()`). `RuleMetadata` and the `GET /api/rules` response carry the platforms too.
- The detection engine scopes each rule's input to the events whose platform is in the rule's declared set. An event carrying no platform is treated as darwin. A rule with no matching events in a batch is skipped.
- All ten current catalog rules declare `darwin`. `dns_c2_beacon` is portable in principle but stays darwin-only until a Windows agent emits `dns_query` events; a later Windows-detection change re-scopes it.
- A catalog guard test asserts every registered rule declares a non-empty set of valid platforms.

## Capabilities

### Modified capabilities

- `server-detection-rules-engine`: rules declare their target platforms, the engine evaluates a rule only against events of those platforms (treating a platform-less event as darwin), and the registered-rule catalog reports each rule's platforms.

## Impact

- Code (rules): a `Platform` type plus constants and `IsValidPlatform` in `server/rules/api` (mirroring the visibility vocabulary, since arch-go forbids a rules-context import of visibility/api); a `Platforms()` method on the `Rule` interface and a `Platforms` field on `RuleMetadata`; the ten catalog `Platforms()` implementations in `server/rules/internal/catalog/platforms.go`; the field populated in the three `RuleMetadata` constructors and surfaced by the operator `GET /api/rules` handler.
- Code (engine): `platformScopedEvents` in `server/detection/internal/engine/filter.go` and its use in `evaluateRule` (`engine.go`).
- Gated path: `server/rules/internal/catalog/` is openspec-sync gated, so this delta ships in the same PR.
- No wire, schema, migration, or persistence change. Behavior is unchanged for a single-platform (all-darwin) fleet: every event matches every rule's set, so the scoping is a no-op fast path.
