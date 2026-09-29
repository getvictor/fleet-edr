## 1. Extension

- [x] 1.1 `CredentialStores`: the browsers, their credential files, the profile listing, and the own-read filter
- [x] 1.2 `CredentialStoreSubscriber`: a NOTIFY_OPEN client muted to the literal files, refreshed every five minutes
- [x] 1.3 Unit tests for the targets, profile detection, the own-read filter and the access mode

## 2. Validation

- [x] 2.1 On edr-dev (SIP off), foreign reads of a Firefox profile (`cp`, `sqlite3`, `cat`) are uploaded as `open` events with their access modes
- [ ] 2.2 Before RC, on edr-qa with a signed build, confirm Firefox's and Chrome's own reads are not reported. edr-dev cannot show this: its ad-hoc extension receives every process's team as empty
