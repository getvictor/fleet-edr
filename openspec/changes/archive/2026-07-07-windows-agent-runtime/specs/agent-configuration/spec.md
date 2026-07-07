## ADDED Requirements

### Requirement: Default file locations are platform-specific

The agent SHALL resolve its default configuration-file, event-queue, and enrollment-token locations from the platform it runs on: `%ProgramData%\FleetEDR\` on Windows, and `/etc/fleet-edr.conf` plus `/var/db/fleet-edr/` on macOS and Linux. An operator MAY still override any location through the existing environment variables; the platform default applies only when the override is unset.

#### Scenario: The agent resolves platform-appropriate default paths

- **GIVEN** an agent started with no path-override environment variables
- **WHEN** it resolves its default configuration
- **THEN** the configuration-file, event-queue, and enrollment-token paths are the platform's default locations
