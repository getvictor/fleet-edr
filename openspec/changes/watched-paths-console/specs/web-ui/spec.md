## ADDED Requirements

### Requirement: Watched file paths are edited in detection tuning

The Detection tuning page SHALL include a Watched file paths section that shows the stored watched-path set, the paths every host always watches, how many of the allowed paths the set uses, and when and by whom it was last saved. An operator with `detection_config.write` SHALL be able to edit a draft of the whole set, and saving it SHALL require a reason and SHALL replace the set through `PUT /api/v1/detection-config/watched-paths`. After a save the section SHALL report how many enrolled hosts the set was queued for. The server SHALL remain the only validator of a path: when it refuses the set, the section SHALL show the server's message and keep the draft. A save SHALL name the version the draft started from, and when the server refuses it because the set has changed since, the section SHALL say so, keep the draft, and offer to load the latest set.

#### Scenario: The console shows the set and what is always watched

- **GIVEN** a stored set with two paths, saved by an operator
- **WHEN** an operator opens Detection tuning
- **THEN** the Watched file paths section lists both paths with whether each covers one file or everything under it
- **AND** it names the paths every host always watches, the number of paths used out of the allowed number, and when and by whom the set was last saved

#### Scenario: A reader cannot change the set

- **GIVEN** an operator with `detection_config.read` and without `detection_config.write`
- **WHEN** they open Detection tuning
- **THEN** the section lists the set with no remove, add, discard or save controls

#### Scenario: An operator saves a changed set with a reason

- **GIVEN** an operator with `detection_config.write` who removes one path and adds another
- **WHEN** they save and give a reason
- **THEN** the whole edited set and the reason are sent in one replace request, and nothing is sent before the reason is given
- **AND** the section reports the saved version and how many of the enrolled hosts the set was queued for, saying the rest receive it within minutes when some could not be queued

#### Scenario: A push that reached no host is called out

- **GIVEN** a save the server stored but could not push because it could not list the enrolled hosts
- **WHEN** the save completes
- **THEN** the section warns that the set was saved but not sent, rather than reporting it as queued for no hosts

#### Scenario: A refused set is shown and the draft kept

- **GIVEN** a draft holding a path the server refuses
- **WHEN** the operator saves it
- **THEN** the section shows the server's refusal message as written
- **AND** the draft is kept for the operator to fix, and editing it clears the message

#### Scenario: A save of an outdated set is refused

- **GIVEN** an operator editing the set loaded at one version, and another operator who has since saved a change
- **WHEN** the first operator saves
- **THEN** the save names the version the draft started from, the server refuses it, and the section says someone changed the watched paths after the page loaded them
- **AND** the draft is kept, and loading the latest set on request replaces the draft with the other operator's set
