# Judge LaunchAgent persistence on the registered program

## Why

`persistence_launchagent` matched `launchctl load` on the command line (issue #1156). That gave it only the plist path to decide on and only a path to exclude by, which is the weakest exclusion there is: an attacker who knows an excluded path writes a file there. It also never saw a plist that becomes active without `launchctl`, which is what happens to one written into `~/Library/LaunchAgents` at the next login.

The daemon rule, `privilege_launchd_plist_write`, already judges Background Task Management registrations on the signature of the program they register, and the extension already reports agent registrations with the same fields. Five of the seven alerts open on the dogfood deployment were this rule and all were benign: three were Apple's own agents and two were vendor updaters.

## What changes

- The rule consumes `btm_launch_item_add` with `item_type` `agent`, through the same gate as the daemon rule: MDM-managed items and Apple platform binaries are skipped, as are registrations whose program's signature cannot be read.
- Exclusions: `team_id` and `signing_id` on the registered program (the latter qualified by the signing team, so an ad-hoc binary cannot claim it), and `path_glob` on the plist.
- The alert is process-optional, like the daemon rule's, and deduplicates on the plist.
- The rule is now an engine rule rather than a Sigma detection block, so its rule file is no longer portable to other Sigma engines.

## Existing data

Existing `path_glob` exclusions keep their meaning: they named the plist then and match the plist now. The extension reports the plist as a `file://` URL, which the rule converts to a path before matching, since an operator writes a path. Existing alerts are unchanged; a new alert deduplicates on the plist rather than on a `launchctl` process.

## Coverage

A plist that becomes active without `launchctl` is now detected. A `launchctl load` of an item launchd has already registered is not re-reported, since no new registration happens; the registration itself was reported when it occurred.

## Not changed

The daemon rule's decisions and its alert subjects are unchanged; it now shares its gate with this rule.
