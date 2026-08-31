# Upstream Sigma rules, verbatim

These are SigmaHQ's macOS rules, copied byte-for-byte from `rules/macos/` and laid out in the same `<category>/` tree upstream uses. They are fixtures for the import path (issue #763), and their being **unmodified** is the property under test: the whole claim is that an upstream file runs here with no edit, so a fixture that had been touched would prove nothing.

Do not tidy, reformat, or reorder them. `TestLoadImported_TheWholeUpstreamCorpus` asserts the exact import and rejection counts, so a change upstream shows up as a test failure to be read rather than absorbed.

Source: https://github.com/SigmaHQ/sigma License: Detection Rule License (DRL) 1.1, https://github.com/SigmaHQ/Detection-Rule-License Each file carries its own `author` and `references` fields, which is where attribution lives.
