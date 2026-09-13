# Upstream Sigma rules, verbatim

These are SigmaHQ's macOS rules, copied byte-for-byte from every rule tree that has any (today `rules/macos/` and `rules-threat-hunting/macos/`) and laid out flat by log-source `<category>/`, the layout `rules/macos/` uses. They are **registered detection rules**, embedded in the binary and evaluated against live events (issue #764), and they are also the fixtures for the import path (issue #763). Their being **unmodified** is the property under test and the property the licence depends on: the whole claim is that an upstream file runs here with no edit, so one that had been touched would prove nothing and would no longer be the rule its author wrote.

Every rule here ships in `monitor` mode: it evaluates and records what it would have fired on, and raises no alert until an operator promotes it.

Do not tidy, reformat, or reorder them. `TestLoadImported_TheWholeUpstreamCorpus` asserts the exact import and rejection counts, so a change upstream shows up as a test failure to be read rather than absorbed.

Source: https://github.com/SigmaHQ/sigma License: Detection Rule License (DRL) 1.1, https://github.com/SigmaHQ/Detection-Rule-License Each file carries its own `author` and `references` fields, which is where attribution lives.

`MANIFEST.sha256` records the SHA-256 of every rule file as vendored. `TestImportedCorpus_MatchesTheVendoredManifest` compares the tree against it, so a local edit, an addition or a deletion fails the build.

Upstream drift is checked by `task sigma:upstream-check` (`tools/sigma-sync`), which compares the tree with SigmaHQ and reports new, changed and withdrawn rules. The `Sigma upstream sync` workflow runs it weekly. When upstream differs, it commits the changes to the `sigma-sync/upstream` branch and keeps an issue titled "Vendored Sigma rules differ from upstream" open with the report and a link that opens the pull request; it closes that issue once the tree matches again. Two differences reach only the issue: a withdrawn rule, which changes no file, and any change while a pull request from the branch is open, which the workflow leaves alone until it merges. `go run ./tools/sigma-sync -apply` copies new and changed rules verbatim and regenerates the manifest. A rule upstream moved to another category is written at its new path and its old copy is removed, since the loader refuses two files with one rule id. It never deletes a rule upstream withdrew, and it never updates the pinned counts in `TestLoadImported_TheWholeUpstreamCorpus`: a new rule should fail that test until someone has read it.
