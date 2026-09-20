## ADDED Requirements

### Requirement: The single sign-on page saves against the configuration it was shown

The single sign-on settings page SHALL send the version of the configuration it is editing with every save, so a save that would replace a change made since the page loaded is refused rather than applied. After a successful save the page SHALL edit against the version that save returned, so an operator can save repeatedly without reloading.

A refused save SHALL be reported as what happened: that nothing was saved, that someone else changed the settings, and that reloading shows their changes. It SHALL NOT be reported as a transport status. A failure that is not a conflict SHALL continue to be reported as itself, because telling an operator to reload does not help with a problem reloading does not fix.

The page SHALL NOT offer to retry a refused save. The operator has not seen the change they would be overwriting, and offering the retry puts the overwrite one click away.

#### Scenario: The page saves against what it was shown

- **GIVEN** an operator on the single sign-on settings page
- **WHEN** they save
- **THEN** the save names the version the page was shown

#### Scenario: A second save names the first's version

- **GIVEN** an operator who has just saved
- **WHEN** they change something and save again without reloading
- **THEN** the second save names the version the first save returned

#### Scenario: A refused save says what happened

- **GIVEN** an operator whose page was open while someone else saved
- **WHEN** they save
- **THEN** they are told nothing was saved, that someone else changed the settings, and to reload
- **AND** they are not shown the transport status
