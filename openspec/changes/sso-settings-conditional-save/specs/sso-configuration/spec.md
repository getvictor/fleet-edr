## ADDED Requirements

### Requirement: A save can name the configuration it was editing

Reading the single sign-on settings SHALL report a version identifying the configuration read, and saving them SHALL accept that version back. A save that names a version SHALL be refused, having written nothing, when the stored configuration has changed since that version was issued. A save that names no version SHALL overwrite what is stored, because automation that means to set the configuration outright should not have to read it first.

The version SHALL cover every separately stored part of the configuration, and a change to any one of them SHALL supersede it. The parts are versioned separately, so a check on one leaves the others open: a save refused only for one part would still overwrite what another operator changed in another, and neither operator would learn.

A version SHALL be read from one consistent snapshot of those parts, on the read and on a save's response alike. Parts read at different moments can pair one part's new version with another's old value, describing a state that never existed; a client sending that version back would pass the check while holding stale data, which is the overwrite this prevents wearing a version number.

A version the system did not issue SHALL be refused rather than treated as absent, because treating it as absent turns the caller's conditional save into the unconditional one, and the caller is told its save was checked when it was not.

Two saves of a configuration that does not exist yet SHALL have one winner, and the loser SHALL be told it was refused. This is the case with nothing stored to compare a version against or to lock, and it SHALL NOT be left to the isolation level to decide.

The version SHALL be opaque to clients: read it, send it back, do not take it apart.

#### Scenario: A save naming a superseded configuration is refused

- **GIVEN** an operator who read the single sign-on settings
- **AND** another operator saved a change afterwards
- **WHEN** the first operator saves, naming the version they read
- **THEN** the save is refused as a conflict
- **AND** the stored configuration is still the other operator's, unchanged

#### Scenario: A change to either stored part supersedes a version

- **GIVEN** an operator who read the single sign-on settings
- **WHEN** any single stored part of the configuration is changed by someone else
- **THEN** the version the operator read no longer matches what is stored
- **AND** a save naming it is refused

#### Scenario: Two first saves have one winner

- **GIVEN** a deployment with no single sign-on configuration stored
- **WHEN** several operators save a first configuration at the same time, each naming the version they read
- **THEN** exactly one save succeeds
- **AND** every other is refused as a conflict
- **AND** the stored configuration is one operator's, whole

#### Scenario: A save naming no version overwrites

- **GIVEN** a script that did not read the settings
- **WHEN** it saves a configuration without naming a version
- **THEN** the save succeeds and replaces what was stored

#### Scenario: A save reports a version that matches what it saved

- **GIVEN** an operator who saves a change
- **WHEN** the save succeeds
- **THEN** it reports the version of the configuration it saved
- **AND** a further save naming that version succeeds without reading again
