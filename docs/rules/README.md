# Rule pack

One declarative rule file per registered detection, generated from the rule catalog. Refresh with `task docs:rule-pack`; a stale or missing file fails CI, so do not hand-edit these.

Each file is standard Sigma metadata plus a single namespaced `x-engine` key holding what Sigma has no concept of: our stable rule id, the rule kind, its portability, the event types it consumes, the evaluator that decides it, the exclusion dimensions it honours, and its known limitations.

## Why every rule says `type: graph` today

A rule is `type: sigma` only when its logic lives in the file's `detection:` block and the engine evaluates it from there. Every detection is currently a Go implementation, so neither half holds and each file honestly reports `type: graph` with `portable: none`.

Writing a `detection:` block by hand to look portable would assert behaviour that nothing verifies. Converting the rules whose logic Sigma can genuinely express, and with them the first real `type: sigma` files, is tracked separately.

## What is missing on purpose

**Parameters.** Thresholds and lists are still unexported Go constants. They move into these files when the engine starts reading them from here, rather than being copied out now into a second place that can disagree with the first.

**Non-detections.** The registry also holds a projection of a decision the agent already made and a health signal about our own agent. Neither has detection logic to inspect, a tuning surface, or an adversary claim, so neither gets a file.

## Fields

| Key                                               | Source                                                                     |
| ------------------------------------------------- | -------------------------------------------------------------------------- |
| `title`, `description`, `level`, `falsepositives` | The rule's operator-facing documentation                                   |
| `id`                                              | A UUID derived from the rule id, because Sigma rejects a slug              |
| `tags`                                            | MITRE ATT&CK techniques, in Sigma's `attack.` vocabulary                   |
| `logsource`                                       | Platform and the Sigma category of the rule's first event type             |
| `x-engine.rule_id`                                | The stable snake_case id that alerts and exclusions key on                 |
| `x-engine.algorithm`                              | The evaluator that decides the rule                                        |
| `x-engine.event_types`                            | Every event type the rule consumes, not just the one `logsource` can carry |
| `x-engine.exclusions`                             | The exclusion dimensions the rule consults                                 |
| `x-engine.limitations`                            | What the rule does not catch                                               |
