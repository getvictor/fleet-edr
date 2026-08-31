# An upstream Sigma rule runs here unmodified

## Why

Choosing Sigma was only worth it if upstream files run as they are. Every key this engine makes mandatory is a key that forks the corpus: a file we have to edit cannot be re-synced without a merge conflict, and its provenance stops being checkable against upstream.

## What the corpus actually needs

Measured against SigmaHQ's 69 macOS rules rather than estimated. The fields they read:

| field | rules using it |
| --- | --- |
| `Image` | 61 |
| `CommandLine` | 59 |
| `ParentImage` | 11 |
| `TargetFilename` | 2 |
| `OriginalFileName` | 1 |

Every one but the last is already supplied. Their modifiers are `contains`, `endswith`, `all`, `re` and `startswith`, all of which the evaluator already implements, and their categories are `process_creation` (67) and `file_event` (2), both of which already map.

So **68 of the 69 import with no enrichment at all.** The issue's acceptance criterion asks for 55; the number is higher because the taxonomy work landed across #786, #788 and #790, and the computed fields those added are not what the upstream corpus reads.

The 69th needs `OriginalFileName`, a Sysmon field naming a PE's embedded original name. macOS has no equivalent, so the rule is refused rather than imported broken.

## What changes

A rule can now be a Sigma file and nothing else. Everything this engine needs that Sigma does not define is derived: the rule id from the filename stem, the platforms from `logsource.product`, the event types from `logsource.category`, the severity from `level`, the techniques from the `attack.t*` tags. No `x-engine` block, no wrapper, no edit.

## Refusing without refusing everything

A file this engine cannot map is reported as a rejection naming the field or category, and the rest of the corpus still imports. Refusing the whole import over one unmappable rule would mean importing nothing, and skipping it silently would leave a rule that is indistinguishable from one that never matches. A file that is unreadable, malformed, or claims an id another file already claimed is a hard error instead, because those say the import itself is broken rather than that one detection does not fit this sensor.

## The gate

The fixtures under `testdata/imported` are **verbatim** SigmaHQ files, and the test asserts they are unmodified by loading them as they are. One of them is the `OriginalFileName` rule, so the rejection path is exercised by the real corpus rather than by a constructed example. A third test runs an upstream rule against a real event through a real store and asserts it fires, and declines the near-miss.

Run against the full macOS corpus with the production loader: 68 imported, 1 rejected, matching the census.

## Impact

Nothing is registered yet. This is the mechanism; #764 imports the corpus in monitor mode and is where anything begins firing.
