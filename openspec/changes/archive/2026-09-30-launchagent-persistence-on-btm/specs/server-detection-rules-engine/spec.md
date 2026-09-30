## ADDED Requirements

### Requirement: LaunchAgent persistence judged on the program

The `persistence_launchagent` rule SHALL consume Background Task Management registrations of LaunchAgents and SHALL judge each on the code signature of the program it registers, not on how the item became active and not on the process that registered it. It SHALL NOT fire for an item that is managed by MDM, whose program is an Apple platform binary, or whose program's signature could not be read.

The rule SHALL consult exclusions of match types `team_id` and `signing_id` against the registered program, the latter qualified by the team that signed it (or by `platform`), and `path_glob` against the plist's filesystem path. A plist reported as a `file://` URL SHALL be matched as the path it names. A finding SHALL name the program and the plist, and SHALL deduplicate on the plist.

#### Scenario: An untrusted agent fires without launchctl

- **GIVEN** a LaunchAgent registration whose program is ad-hoc signed and not MDM-managed, with no `launchctl` execution in the batch
- **WHEN** the rule evaluates it
- **THEN** one finding is produced naming the program and the plist as a path

#### Scenario: An Apple or managed agent does not fire

- **GIVEN** a LaunchAgent registration whose program is an Apple platform binary, and another that MDM manages
- **WHEN** the rule evaluates them
- **THEN** no finding is produced

#### Scenario: A vendor agent is waived by its signer

- **GIVEN** a `team_id` exclusion for a vendor, or a `signing_id` exclusion naming that vendor's team and identifier
- **WHEN** a LaunchAgent registration whose program that vendor signed is evaluated
- **THEN** no finding is produced

#### Scenario: An ad-hoc binary cannot claim a signer

- **GIVEN** a `signing_id` exclusion for a vendor's identifier, qualified or bare
- **WHEN** a LaunchAgent registration whose ad-hoc signed program claims that identifier with no team is evaluated
- **THEN** a finding is produced

#### Scenario: A plist path exclusion keeps working

- **GIVEN** a `path_glob` exclusion naming a plist by its path
- **WHEN** a registration reporting that plist as a `file://` URL is evaluated
- **THEN** no finding is produced

## MODIFIED Requirements

### Requirement: An exclusion covers only what it names

A persistence rule SHALL judge each registered item on its own. An exclusion SHALL suppress the finding only for the item it names, and a finding's description SHALL name the item it was raised for.

`launchctl` accepts several plist paths in one invocation, and the rule once read back only the first, so an exclusion for a benign plist suppressed whatever was registered alongside it:

```sh
launchctl load /Library/LaunchAgents/com.logi.ghub.plist ~/Library/LaunchAgents/evil.plist
```

Planting a plist under `/Library/LaunchAgents` needs root; this needed none, because the first argument only had to NAME an excluded plist and the second was the user's own LaunchAgent. Each plist is now its own registration, judged and reported separately, so what an exclusion names is exactly what it covers.

#### Scenario: An excluded registration does not cover its neighbour

- **GIVEN** an exclusion for a benign LaunchAgent plist
- **AND** registrations of that plist and of a second plist the exclusion does not cover
- **WHEN** the engine evaluates the rule
- **THEN** one finding is produced
- **AND** its description names the second plist and not the excluded one

#### Scenario: Every registration excluded suppresses every finding

- **GIVEN** exclusions covering each of several LaunchAgent plists
- **AND** registrations of exactly those plists
- **WHEN** the engine evaluates the rule
- **THEN** no finding is produced

#### Scenario: Several registrations are each reported

- **GIVEN** registrations of several LaunchAgent plists and no exclusion for any of them
- **WHEN** the engine evaluates the rule
- **THEN** one finding is produced for each, naming its plist
