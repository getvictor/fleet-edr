# Tasks

## 1. Retryable sentinel + grace helper

- [x] 1.1 Add `ErrProcessNotYetMaterialized` to `rules/api` and document the retry contract on `Rule.Evaluate`.
- [x] 1.2 Add `resolveSubjectProcess` + `withinMaterializationGrace` (30s compiled constant) to the catalog.
- [x] 1.3 Wire the helper into the subject-pid lookups of sudoers_tamper, credential_keychain_dump, application_control_block, persistence_launchagent, dyld_insert, shell_from_office, osascript_network_exec, and suspicious_exec; leave ancestor walks and dns_c2_beacon flow resolution on silent skip (documented in the helper).

## 2. Engine propagation

- [x] 2.1 `evaluateRule` returns an error wrapping the sentinel (processor nacks + retries the batch); every other rule failure keeps log-and-swallow isolation.

## 3. Demo seeder verify

- [x] 3.1 `verify` polls for a fired alert per woven attack's `ExpectRule` and names the missing rules in its timeout error.

## 4. Tests

- [x] 4.1 Rule level: young miss raises the sentinel; past-grace miss skips silently; materialized row yields the finding; grace-window edges (zero ingest stamp, exact boundary).
- [x] 4.2 Engine level: the sentinel propagates out of `Evaluate`; an ordinary rule failure does not.
- [x] 4.3 Seeder: per-rule fired set feeds the verify predicate; end-to-end run seeds one alert per expected rule.
