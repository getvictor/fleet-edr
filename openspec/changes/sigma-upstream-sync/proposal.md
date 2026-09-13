# The vendored Sigma corpus is checked against upstream

Issue #1003. The vendored SigmaHQ macOS rules are pinned by a manifest test, which catches an edit, addition or deletion made here. Nothing caught upstream drift: a rule SigmaHQ fixes for a false positive, or withdraws as wrong, stayed as vendored indefinitely, and a macOS rule published in a tree other than `rules/` was never noticed. Two already exist in `rules-threat-hunting/macos`.

## What changes

- **`tools/sigma-sync`** compares the vendored tree with one snapshot of SigmaHQ. It covers every rule tree (`rules` and any `rules-*`), and a `macos` directory at any depth within one, so a tree that gains macOS rules is noticed. Rules are matched by rule id, the case-folded file stem the corpus loader identifies them by, and compared by git blob id, so an unchanged rule is never downloaded. It reports new rules, changed rules, rules upstream moved to another category, and rules no longer among upstream's rules, noting when upstream moved one to `deprecated/`. The report exits non-zero when anything differs (`task sigma:upstream-check`).
- **`-apply`** copies new, changed and moved rules verbatim, and removes a moved rule's old copy, since two files with one rule id would stop the corpus loading. Every download is checked against its blob id before anything is written, so a bad download leaves the tree unchanged. It then regenerates the manifest. It never deletes a withdrawn rule and never updates the pinned import and refusal counts, so a new rule fails `TestLoadImported_TheWholeUpstreamCorpus` until someone has read it.
- **Two rules imported through it** from `rules-threat-hunting/macos`. `proc_creation_macos_pbpaste_execution` imports in monitor mode, with a regression fixture. `file_event_macos_python_path_configuration_files` is refused by name like the other file_event rules, because this agent emits no file events for the paths it watches. The corpus is now 71 files: 68 import and 3 are refused.
- The generated rule reference and ATT&CK layer are regenerated.
- **A weekly workflow** runs the check from main. When upstream differs, it commits the result to `sigma-sync/upstream`, runs the catalog tests, and keeps one tracking issue with the report, the test result and a link that opens the pull request, closing it when the corpus matches again. It leaves a branch with an open pull request alone, never overwrites a branch that changed after it looked, and reports a withdrawal without touching the branch. It does not open the pull request itself: this repository does not let Actions create pull requests, and one opened with the workflow token would not start CI.

## Out of scope

- Non-macOS trees, until there is an agent for that platform.
