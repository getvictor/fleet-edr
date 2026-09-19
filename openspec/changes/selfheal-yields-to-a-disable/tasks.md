# Tasks

- [x] Keep the cancel for the enable in flight on the provider's controller state, set under the lock at the moment the attempt is planned.
- [x] Cancel it and drop the episode when a report says the provider is `disabled`, and only then, never on absence.
- [x] Match a finished attempt to the episode it was launched for by identity, and discard it when that episode is over.
- [x] Add `ProviderDisabled` to `agent/selfheal`, mirroring the extension's wire value.
- [x] Tests for the abandoned enable, absence not abandoning one, the fresh budget afterwards, and the outlived attempt (including on the last attempt of a budget); mutation-check them.
- [ ] Exercise on a live macOS VM: disable a provider while a remediation is running and confirm it stays disabled.
