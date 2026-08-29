# Tasks

- [x] Move the pack beside the code that reads it, leaving exactly one canonical copy.
- [x] Load and validate the embedded pack, with a parameter schema registered per algorithm.
- [x] Refuse a parameter the algorithm never reads, and a declared parameter the file omits.
- [x] Refuse a malformed or non-positive duration, and an empty match list.
- [x] Read eight parameters from files across five rules.
- [x] Move the three cross-rule lists into shared definitions rather than copying them per rule.
- [x] Preserve the authored parameter block verbatim through regeneration, comments included.
- [x] Stop the generator pruning the authored shared-list file.
- [x] Keep every existing rule test passing unmodified.
