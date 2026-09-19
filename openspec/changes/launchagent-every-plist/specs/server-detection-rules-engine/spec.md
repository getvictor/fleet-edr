## ADDED Requirements

### Requirement: An exclusion covers only what it names

A rule whose detection matches on a command argument SHALL evaluate EVERY argument the detection matched, not the first. It SHALL suppress the finding only when an operator exclusion covers all of them, and the finding's description SHALL name the candidates that were not excluded.

`launchctl` accepts several plist paths in one invocation, and `persistence_launchagent` read back only the first. An exclusion for a benign plist therefore suppressed whatever was registered alongside it:

```sh
launchctl load /Library/LaunchAgents/com.logi.ghub.plist ~/Library/LaunchAgents/evil.plist
```

Planting a plist under `/Library/LaunchAgents` needs root; this needs none, because the first argument only has to NAME an excluded plist and the second is the user's own LaunchAgent. The description had the same shape of fault with no exclusion at all: it named the first argument, so an analyst reading the alert never learned the second plist had been registered.

#### Scenario: An excluded candidate does not cover its neighbour

- **GIVEN** an exclusion for a benign LaunchAgent plist
- **AND** a `launchctl load` naming that plist and a second plist the exclusion does not cover
- **WHEN** the engine evaluates the rule
- **THEN** a finding is produced
- **AND** its description names the second plist and not the excluded one

#### Scenario: Every candidate excluded suppresses the finding

- **GIVEN** exclusions covering each of several LaunchAgent plists
- **AND** a `launchctl load` naming exactly those plists
- **WHEN** the engine evaluates the rule
- **THEN** no finding is produced

#### Scenario: Several candidates are all named

- **GIVEN** a `launchctl load` naming several LaunchAgent plists and no exclusion for any of them
- **WHEN** the engine evaluates the rule
- **THEN** the finding's description names every one of them
