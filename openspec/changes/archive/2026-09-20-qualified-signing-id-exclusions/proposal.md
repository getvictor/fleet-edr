# A signing_id exclusion names the team that signed it

Issue #1024. A `signing_id` exclusion suppressed a finding for any binary that merely CLAIMED the identifier. The identifier is not an identity: it is whatever the signer put in the binary, and an ad-hoc signature sets it to anything with no privilege and no Apple account.

```sh
codesign -s - -i com.anthropic.claude-code ./payload
```

That binary has no team ID, runs on Apple Silicon, and inherited every exclusion written for the real vendor's tool. Until #1023 our own documentation called `signing_id` "non-spoofable" and recommended it as the more specific alternative to `team_id`, so operators following the guidance built exactly this bypass.

## What changes

- **The value is qualified**: `<TEAMID>:<identifier>`, or `platform:<identifier>` for a binary the operating system ships. This is Santa's spelling, because an operator comparing the two products should not have to learn a second one. Jamf Protect requires the Team ID alongside the Signing ID for the same reason.
- **The match composes the candidate rather than loosening the matcher.** The resolver still compares for equality; `api.QualifiedSigningID` builds what the parent's signature composes to, and an ad-hoc parent composes to the empty string, which equals no exclusion. The security property is therefore a property of the composer, in one place, rather than of every call site.
- **The create API refuses a bare value**, naming both accepted forms. An exclusion that can never match is one an operator believes is suppressing something.
- **Platform is checked before team**, because Apple's binaries carry no team ID and the team branch would otherwise discard them. The platform flag is the one qualifier a planted binary cannot set.

## Existing rows

A stored bare value now matches nothing, because every candidate is composed with a qualifier. That is the fail-safe direction: those exclusions stop suppressing, so the rule fires where it used to be silent, rather than a blind spot persisting. No migration rewrites them, because the team that should qualify them is not knowable from the stored value.

Operators must be told, so this ships an upgrade note: any `signing_id` exclusion written before this release has stopped suppressing and needs rewriting with its team. `codesign -dv <binary>` prints both fields.

## Documentation was wrong in the other direction

`docs/recommended-exclusions.md` told operators not to rely on `signing_id` at all and to use `team_id` instead, which was correct advice for the old behaviour and is wrong for the new one. It now describes `signing_id` as the way to narrow a team to one of its tools. `docs/operations.md` carried the same warning and is corrected too.

## Out of scope

Signature validity checks in the agent's static code-signing read (`agent/codesign/codesign_darwin.go`), which reads team and identifier without `SecStaticCodeCheckValidity`. That affects `privilege_launchd_plist_write` and wants its own issue.
