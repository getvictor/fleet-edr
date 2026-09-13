## ADDED Requirements

### Requirement: Hosts that miss the watched-path push get the set

The server SHALL periodically queue the current watched-path set, as a `set_watched_paths` command carrying the same `{version, epoch, paths}` the push sends, for every host with an active enrollment whose latest `set_watched_paths` command does not already carry it. A host SHALL be sent the set when it has no such command, when that command carried an older version, when it was queued before the host's latest enrollment, when it expired or was cancelled, or when it failed at least six hours ago.

A pending, acknowledged, or completed command at the current version, queued since the host's latest enrollment, SHALL count as delivered, so a host that is offline is not sent a new copy every time the server checks. A failed command SHALL count as delivered for six hours before the set is queued again, so a host whose agent cannot run the command does not accumulate a failed command every check.

While the set has never been changed, the server SHALL queue nothing.

#### Scenario: A host enrolled after a change gets the set

- **GIVEN** a watched-path set was changed while a host was not yet enrolled
- **WHEN** the host has enrolled and the server next checks
- **THEN** the current set is queued for that host, carrying the same version and epoch the push carried
- **AND** it is not queued again while that command is pending

#### Scenario: An expired or reinstalled host gets the set again

- **GIVEN** a host whose command for the current set expired undelivered, and a host that took the set and then enrolled again after a reinstall
- **WHEN** the server next checks
- **THEN** the current set is queued for both hosts
