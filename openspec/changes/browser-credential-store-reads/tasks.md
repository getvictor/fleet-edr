## 1. Extension

- [x] 1.1 `CredentialStores`: the browsers, their credential files, the profile listing, and the own-read filter
- [x] 1.2 `CredentialStoreSubscriber`: a NOTIFY_OPEN client muted to the literal files, refreshed every five minutes
- [x] 1.3 Unit tests for the targets, profile detection, the own-read filter and the access mode
- [x] 1.4 Past 50 profiles in one browser directory, watch it as a prefix and filter opens to the credential files, so a user creating profile directories can neither grow the muted set without limit nor crowd a real profile out
- [x] 1.5 On edr-dev, with 51 decoy Firefox profiles, a foreign read of the real profile's `logins.json` is reported and Firefox's other files are not

## 2. Validation

- [x] 2.1 On edr-dev (SIP off), foreign reads of a Firefox profile (`cp`, `sqlite3`, `cat`) are uploaded as `open` events with their access modes
- [ ] 2.2 Before RC, on edr-qa with a signed build, confirm Firefox's and Chrome's own reads are not reported. edr-dev cannot show this: its ad-hoc extension receives every process's team as empty
