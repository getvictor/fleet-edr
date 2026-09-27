# Push default watched paths so shipped file rules can fire

## Why

The agent emits file events only for paths it is told to watch: the extension's built-in sudoers paths and whatever an operator adds. So the importer refused every SigmaHQ `file_event` rule, including two the product already carried for macOS persistence, Emond (T1546.014) and startup items (T1037.005), because nothing guaranteed any host watched their paths (issue #1167).

## What changes

- The server pushes a set of default watched paths to every host on top of the operator's set: `/etc/emond.d/rules/`, `/private/var/db/emondClients/` and `/Library/StartupItems/`. They are reported as always watched beside the extension's built-ins, and are not in the set an operator edits.
- Each stored version of the set records the defaults it was stored with. When the server's defaults differ, including on a deployment that never configured a set, the converge loop stores the operator's same paths again as a system change, so the version and epoch move and hosts apply it. Server-only: agents already deployed apply it.
- The importer decides file rules by their paths, not by category: a rule is imported when every search pins `TargetFilename` inside the always-watched set, and refused whenever that cannot be proven. The two rules above now load, in monitor mode like the rest of the imported corpus.

## Not changed

Operator paths, the set's limits, and the push and catch-up mechanics are unchanged. A stored set written before this change decodes as it was.
