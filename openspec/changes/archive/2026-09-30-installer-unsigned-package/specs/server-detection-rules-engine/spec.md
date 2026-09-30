## ADDED Requirements

### Requirement: An unsigned installer package is reported

The `installer_unsigned_package` rule SHALL fire on an `exec` event whose `package_signing` is present and not `signed`: an installer script run from a package that is unsigned or whose signature macOS does not trust. It SHALL NOT fire on an exec whose package is signed, or on an exec without `package_signing`, which the agent attaches only to an installer script. The finding SHALL name the script and the package, link to the script's process, and deduplicate per package, so a package's several scripts raise one alert. An exclusion for the rule SHALL suppress it by a path glob on the package's path.

#### Scenario: An unsigned package's script fires

- **GIVEN** an installer script's exec whose `package_signing` says the package is not signed
- **WHEN** detection evaluates the event
- **THEN** `installer_unsigned_package` raises a high-severity finding naming the script and the package, linked to the script's process

#### Scenario: A signed package or an ordinary exec does not fire

- **GIVEN** an installer script's exec from a signed package, and the same exec with no `package_signing`
- **WHEN** detection evaluates the events
- **THEN** no finding is raised

#### Scenario: One alert per package

- **GIVEN** a package's preinstall and postinstall execs, and a script from another package, all unsigned
- **WHEN** detection evaluates the events
- **THEN** the first package's two findings share one dedup subject, and the other package's finding has its own

#### Scenario: An unsigned package is waived by its path

- **GIVEN** an exclusion for `installer_unsigned_package` with a path glob matching the package's path
- **WHEN** detection evaluates the package's script
- **THEN** no finding is raised
- **AND** the same glob saved for another rule does not suppress it
