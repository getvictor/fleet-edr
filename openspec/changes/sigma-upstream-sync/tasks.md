# Tasks

- [x] Add `tools/sigma-sync` with a check that reports new, changed and withdrawn upstream rules across every SigmaHQ rule tree.
- [x] Add `-apply`: verbatim copies verified against the blob id, manifest regeneration, no deletion, no count updates.
- [x] Import the two `rules-threat-hunting/macos` rules, add the pbpaste fixture, and update the pinned counts deliberately.
- [x] Regenerate the rule reference and ATT&CK layer; add `task sigma:upstream-check`.
- [x] Add the weekly workflow: review branch, catalog tests reported, branches under review left alone.
- [x] Open the pull request with a GitHub App token, and keep the tracking issue for withdrawals and changes found while a pull request is open.
