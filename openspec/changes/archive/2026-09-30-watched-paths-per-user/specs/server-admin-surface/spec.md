## ADDED Requirements

### Requirement: A watched path can name every user's home

The server SHALL accept in the watched-path set an entry whose path starts with `~/`, which names the same path in every user's home folder, and SHALL judge it as the path it would be in a home at the root: every rule an absolute path meets applies, with a prefix's depth counted below the home. It SHALL refuse `~/` alone, and a `~/` prefix naming a top-level directory of the home.

#### Scenario: A path in every home is judged below the home

- **GIVEN** a proposed set with `~/.ssh/authorized_keys` as a literal and `~/Library/LaunchAgents/` as a prefix
- **WHEN** the operator saves it
- **THEN** the server accepts it
- **AND** it refuses a set holding `~/` or `~/Library/` as a prefix, or a `~/` entry with an empty or `..` segment
