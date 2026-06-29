# Name each detection one canonical way across docs, the rule catalog, and the alert

## Why

Every detection rule names itself through three independent surfaces that do not agree, so an operator sees a different string for the same detection depending on where they look (issue #519):

1. **Rule ID** (`ID()`, snake_case) in `/api/rules`, `alerts.rule_id`, exclusions, and the efficacy corpus.
2. **Doc title** (`Doc().Title`) in `/api/rules` and `docs/detection-rules.md`.
3. **Alert title** (`Finding.Title`) in the alerts list and alert detail.

For the LaunchDaemon-persistence rule the same detection is variously "LaunchDaemon persistence (BTM daemon registration)" (doc), "LaunchDaemon persistence" (alert), and `privilege_launchd_plist_write` (ID). Worse, `suspicious_exec` emitted two unrelated alert titles ("Shell spawn with outbound network connection" and "Suspicious exec from temp path"), neither matching its doc title. A user triaging an alert, reading the docs, and writing an exclusion has to mentally map several strings to one detection. Detection catalogs (Sigma, Elastic, MITRE-aligned vendor rules) instead give each detection a stable identifier plus one canonical human-readable name reused everywhere; the alert names the rule you can look up.

## What changes

- **Each rule exposes one canonical `DisplayName()`** on the `api.Rule` interface. Both `Doc().Title` and `Finding.Title` derive from it, so the docs, `/api/rules`, and the alert show the same name. The name is a clean human-readable label; the parenthetical implementation detail that several doc titles carried (`(security dump-keychain)`, `(launchctl load/bootstrap)`, etc.) lives in `Summary`, not the title.
- **Observable alert titles change** for the rules whose finding title diverged from the canonical name: `suspicious_exec` (both arms now "Suspicious exec chain"; which arm fired stays in the finding Description), `persistence_launchagent`, `dyld_insert`, `shell_from_office`, `osascript_network_exec`, `credential_keychain_dump`. Documented rule titles change for the rules that carried a parenthetical.
- **Rule IDs are unchanged.** Renaming an ID (e.g. the semantically stale `privilege_launchd_plist_write`) is a separate, migration-backed change: IDs key `alerts.rule_id`, exclusions, the efficacy corpus, and generated docs.
- **A structural guard prevents re-drift.** A catalog test asserts `Doc().Title == DisplayName()` for every rule and that the name is a clean label; the fixture-replay harness and each rule's positive-detection test assert `Finding.Title == DisplayName()`.
- `docs/detection-rules.md` is regenerated from the new titles.

### Not in this change

- No rule-ID rename (separate migration-backed change).
- `application_control_block` keeps its per-block computed alert title (`Application blocked: <binary>`) and its per-rule `app_control:<n>` RuleID: its alerts name the blocked binary and the admin rule, not a catalog detection. `DisplayName()` ("Application control block") still backs its `Doc().Title`. It is the one rule exempt from the finding-title==DisplayName assertion.
- No wire-shape change: `Doc().Title` stays the surfaced field, now guaranteed canonical.
