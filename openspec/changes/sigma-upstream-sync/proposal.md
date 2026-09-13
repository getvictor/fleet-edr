# The vendored Sigma corpus is checked against upstream

Issue #1003. The vendored SigmaHQ macOS rules are pinned by a manifest test, which catches an edit, addition or deletion made here. Nothing caught upstream drift: a rule SigmaHQ fixes for a false positive, or withdraws as wrong, stayed as vendored indefinitely, and a macOS rule published in a tree other than `rules/` was never noticed. Two already exist in `rules-threat-hunting/macos`.

## What changes

- **`tools/sigma-sync`** compares the vendored tree with one snapshot of SigmaHQ. It covers every rule tree (`rules` and any `rules-*`), and a `macos` directory at any depth within one, so a tree that gains macOS rules is noticed. Files are compared by git blob id, so an unchanged rule is never downloaded. It reports new rules, changed rules, and rules no longer among upstream's rules, noting when upstream moved one to `deprecated/`. The report exits non-zero when anything differs (`task sigma:upstream-check`).
- **`-apply`** copies new and changed rules verbatim. Every download is checked against its blob id before anything is written, so a bad download leaves the tree unchanged. It then regenerates the manifest. It never deletes a withdrawn rule and never updates the pinned import and refusal counts, so a new rule fails `TestLoadImported_TheWholeUpstreamCorpus` until someone has read it.
- **Two rules imported through it** from `rules-threat-hunting/macos`. `proc_creation_macos_pbpaste_execution` imports in monitor mode, with a regression fixture. `file_event_macos_python_path_configuration_files` is refused by name like the other file_event rules, because this agent emits no file events for the paths it watches. The corpus is now 71 files: 68 import and 3 are refused.
- The generated rule reference and ATT&CK layer are regenerated.

## Out of scope

- The scheduled job that runs the check weekly and opens a pull request. It follows in its own change.
- Non-macOS trees, until there is an agent for that platform.
