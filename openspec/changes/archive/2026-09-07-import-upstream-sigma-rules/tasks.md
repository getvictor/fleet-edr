# Tasks

- [x] A rule can be a plain Sigma file with no `x-engine` block
- [x] Rule id defaults to the filename stem
- [x] Platforms, event types, severity and techniques derived from the file
- [x] An unmappable rule is rejected by name, and the rest still import
- [x] A malformed or duplicate-id file fails the import
- [x] An upstream rule fires on a matching event
- [ ] Register the corpus in monitor mode (#764)
- [ ] Report upstream additions, changes and removals on re-sync (#763 follow-up)
