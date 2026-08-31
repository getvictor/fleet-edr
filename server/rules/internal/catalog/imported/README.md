# Upstream Sigma rules, verbatim

These are SigmaHQ's macOS rules, copied byte-for-byte from `rules/macos/` and laid out in the same `<category>/` tree upstream uses. They are fixtures for the import path (issue #763), and their being **unmodified** is the property under test: the whole claim is that an upstream file runs here with no edit, so a fixture that had been touched would prove nothing.

Do not tidy, reformat, or reorder them. `TestLoadImported_TheWholeUpstreamCorpus` asserts the exact import and rejection counts, so a change upstream shows up as a test failure to be read rather than absorbed.

Source: https://github.com/SigmaHQ/sigma License: Detection Rule License (DRL) 1.1, https://github.com/SigmaHQ/Detection-Rule-License Each file carries its own `author` and `references` fields, which is where attribution lives.

`MANIFEST.sha256` records the SHA-256 of every rule file as vendored. `TestImportedCorpus_MatchesTheVendoredManifest` compares the tree against it, so a local edit, an addition or a deletion fails the build. Nothing offline can check these files against upstream, but that test does catch the half that decays in practice: drift introduced here after the import. Regenerate the manifest as part of a deliberate re-sync, never to make the test pass.
