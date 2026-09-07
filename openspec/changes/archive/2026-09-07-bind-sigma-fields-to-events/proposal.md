# Bind Sigma field names to our event payloads

## Why

#786 landed an evaluator that matches Sigma rules against an `Event` interface, deliberately knowing nothing about our events. Nothing implements that interface, so no rule can be evaluated against real telemetry. This is the other half of #760: the mapping from Sigma's field names onto our payloads, and the load-time check that refuses a rule reading a field we do not supply.

## What changes

A new `server/rules/internal/sigmabind` package. It decodes an event once into the Sigma fields it can supply, resolves a rule's `logsource` category to one of our event types, and validates a compiled rule against the taxonomy before it is ever evaluated.

## The field set is measured

Across the 69 macOS SigmaHQ rules there are exactly five distinct detection fields: `CommandLine` (107 uses), `Image` (85), `ParentImage` (16), `TargetFilename` (5) and `OriginalFileName` (1).

Three are supplied: `Image` from an exec payload's resolved `path`, `CommandLine` from its argv joined by spaces, and `TargetFilename` from a file-open payload's `path` **when the open carries write intent**.

That last qualifier matters. Sigma's `file_event` means file creation or modification (it is Sysmon's FileCreate), not "a file was opened". Our open events include read-only opens, and those are routine rather than signal: the existing `sudoers_tamper` rule drops them precisely because cron, sudo itself and various PAM modules read `/etc/sudoers` constantly. Supplying `TargetFilename` for a read-only open would import that noise into every `file_event` rule we ever adopt, as false positives rather than as a visible error. Write intent is derived from the open(2) access mode until #772 carries it explicitly. **57 of the 69 macOS rules load against that taxonomy.**

The other two are absent, and their absence is the load check working rather than a gap to paper over:

- `ParentImage` needs the parent's executable path on an exec event. Our payload carries `ppid` but not the parent's path, so it waits on the enrichment in #771. Its 16 uses span 11 distinct rules, and those 11 are blocked today, loudly.
- `OriginalFileName` is a Windows PE version-resource field with no macOS equivalent. No enrichment will supply it, and inventing a value would misrepresent what we know.

## CommandLine is argv joined, and argv[0] is left alone

Measured on a live host, argv[0] is whatever the caller passed: `/usr/sbin/sshd` reports a full path while `xpcproxy` reports a bare name. Rewriting it to the resolved executable path was considered and rejected: none of the 203 `CommandLine` match values across the macOS corpus contains a path separator, so no rule wants it, and `Image` already carries the resolved path for rules that do.

## Impact

No behaviour change: nothing calls the package yet. #761 is the first consumer, and this unblocks three of the five rules it converts (`credential_keychain_dump`, `persistence_launchagent`, `dyld_insert`); the other two wait on #771 and #772 as that issue already records.
