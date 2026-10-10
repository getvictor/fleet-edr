## 1. Extensions

- [x] 1.1 The production XPC peer requirement pins `identifier "fleet-edr-agent"` alongside the anchor and team ID; checked with `codesign -R` against the released agent
- [x] 1.2 Swift unit tests pin the full production requirement

## 2. Server and UI

- [x] 2.1 `requires_fresh_auth` adds `rule_content.write`, `detection_config.write` and `enrollment.revoke`; example and property tests updated
- [x] 2.2 The detection-tuning page and the watched-paths editor wrap their writes in the reauth prompt; tests show the prompt on a stale session

## 3. Docs

- [x] 3.1 Threat model, ADR-0007 amendment, install-server reauth row
