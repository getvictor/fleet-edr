# A LaunchAgent exclusion covers only the plist it names

Issue #1028. `persistence_launchagent` matched when ANY `launchctl load` or `bootstrap` argument was a LaunchAgent plist, then read back only the FIRST matching argument and checked the exclusion against that one. `launchctl` takes several paths in one invocation, so an exclusion for a benign plist suppressed whatever was registered alongside it:

```sh
launchctl load /Library/LaunchAgents/com.logi.ghub.plist ~/Library/LaunchAgents/evil.plist
```

Dogfood carries an exclusion for `/Library/LaunchAgents/com.logi.*.plist`. Planting a plist under `/Library/LaunchAgents` needs root; this bypass needs none, because the first argument only has to NAME the excluded plist and the second is the user's own LaunchAgent.

The description had the same fault independently of any exclusion: it named the first argument only, so an analyst reading the alert never learned the second plist had been registered.

## What changes

- **`allMatching`**, the plural of the existing `firstMatching`, returns every value of a multi-valued field satisfying a predicate. A rule that reads only the first decides on one candidate while the rest go unexamined, and that is a shape worth naming once rather than fixing in place.
- **The rule evaluates every plist argument** and suppresses only when the operator has excluded all of them. One unexcluded plist is the whole finding.
- **The description names the plists that were NOT excluded**, so an analyst sees what the exclusion left behind rather than a path that was already accounted for.

## Why the requirement is written generally

The delta states the rule for any detection that matches on a command argument, not just this one. The fault is not specific to `launchctl`: it is what happens whenever a detection matches on "any of these" and the decision then reads "the first of these". Writing it narrowly would leave the next rule with several candidates free to repeat it.

Only `persistence_launchagent` has several candidates today, so that is the only rule this changes.

## Out of scope

Signature-based exclusions for this rule (#993).
