## ADDED Requirements

### Requirement: A watched path can name every user's home

A watched path that starts with `~/` SHALL name the same path in every user's home folder. The extension SHALL accept such an entry under the rules it applies to an absolute path, judged as the path it would be in a home at the root, so that a prefix names something at least two components below the home. It SHALL expand the entry into one path in each home it reads from the directory service: root's, and each account with a user ID of 500 or above whose home is an absolute path other than a placeholder, once each. An expansion that the extension would not watch as an absolute path SHALL be left out. The extension SHALL re-read the accounts at least every five minutes and re-apply the set when they have changed, so an account added after the set was pushed is watched without another push.

#### Scenario: A home entry is judged below the home

- **GIVEN** pushed entries `~/.ssh/authorized_keys` (literal), `~/Library/LaunchAgents/` (prefix) and `~/Library/` (prefix)
- **WHEN** the extension decodes the set
- **THEN** it accepts the first two and refuses `~/Library/`, as it refuses `/Library/`

#### Scenario: A home entry covers root and every person's home

- **GIVEN** accounts for root, two people, a system account, and an account whose home is the `/var/empty` placeholder
- **WHEN** the extension expands `~/.ssh/authorized_keys`
- **THEN** it watches the file in root's home and in each person's home, once each, and in no other
