# Tasks

- [x] Add `allMatching`, the plural of `firstMatching`, for a multi-valued field.
- [x] Evaluate every LaunchAgent plist argument and suppress only when all are excluded.
- [x] Name the non-excluded plists in the finding description.
- [x] Table-driven cases: the issue's exact command, several plists all excluded, and several with no exclusion; mutation-check each.
- [ ] Confirm on a VM that a two-plist `launchctl load` with one excluded still raises a finding.
