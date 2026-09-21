# Tasks

- [x] Store the watched-path set as one versioned row
- [x] Validate a proposed set: size, path shape, match rules, duplicates, top-level prefixes
- [x] GET and PUT routes gated on detection_config read and write
- [x] Queue set_watched_paths for every enrolled host on a change, and audit it with its reason
- [x] Live exercise against a real agent and extension
