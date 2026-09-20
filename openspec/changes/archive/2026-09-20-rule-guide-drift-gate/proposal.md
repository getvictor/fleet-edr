# Fail the build when the rule guide lags the catalog

Issue #1105. `docs/detection-rules.md` is generated from the rule catalog by `tools/gen-rule-docs`, and nothing compared it with what the catalog would produce now. A change to a rule's `Doc()` that did not also run `task docs:rules` shipped operator documentation contradicting the code, with review the only thing in the way. That happened on #1103: `sensor_tamper`'s description was updated to say a deliberately disabled provider is reported `disabled`, while the published guide still told operators it was reported as absent. A reviewer caught it; no check did.

## A correction to the issue

The issue says nothing in CI compares the generated files, and asks for a check covering both the guide and the rule pack. The pack half already exists and works: `TestPackHasNoDrift` in `server/rules/bootstrap` compares every rule file against `ExportPack()` and fails naming the file and `task docs:rule-pack`. It was verified here by changing a rule's `Doc()` and watching it fail. So the gap was the guide alone, and that is what this adds.

## What changes

- **`TestCommittedDocsHaveNoDrift`** renders the guide through `render`, the same function the generator writes with, and compares it against the committed `docs/detection-rules.md`. Comparing against the generator's own output rather than a second rendering is the point: two descriptions of the same rules can agree with each other while both disagree with the catalog.
- **The failure names one line, not a 2,400-line diff.** A testify diff of the whole guide buries the single line that changed, which is the only line the author needs in order to see what they forgot. The message gives the first differing line, both versions of it, and `task docs:rules`.
- **`firstDifference` is itself tested**, on documents of differing lengths in both directions. A differ that walked only the shorter document would report no difference when a rule was added or removed, which is the drift guard silently passing.
- **Two stale comments corrected.** `server/apidocs/openapi_drift_test.go` and `server/rules/bootstrap/pack_test.go` both state that CI does not run `./tools/...` and place themselves under `server/` on that basis. It has run `./tools/...` since #1053 (2026-09-14), which is what makes a guard next to the generator count. Left uncorrected, the next person writing a drift check reasons from a false premise, in the comments written to stop exactly that.

## Why the test sits next to the generator

The two existing drift guards live under `server/` because when they were written a test under `tools/` would never have executed, which is how #780 happened. That constraint is gone. The guide's guard goes next to the generator it guards, where the `render` function it must not diverge from is in the same file, and its comment records the dependency on the task's package list rather than leaving it implicit.
