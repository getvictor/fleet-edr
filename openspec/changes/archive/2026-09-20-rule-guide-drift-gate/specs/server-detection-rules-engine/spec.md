## ADDED Requirements

### Requirement: The rule guide matches the registered detections

The system SHALL keep the generated operator rule guide in agreement with the registered detections, and a guide that has drifted SHALL fail the build, naming the file and the command that regenerates it.

The guide is what an operator reads to decide whether a detection is worth tuning, suppressing or trusting. A description that lags the rule is worse than a missing one: it reads as current and is wrong, and the reader has no way to tell. The rule pack is already held to this; the guide is the half that operators actually read.

The check SHALL compare the committed guide against what the generator itself renders, rather than against a second description of the same rules, so that the two cannot agree with each other while both disagree with the catalog.

#### Scenario: A guide that lags the catalog fails the build

- **GIVEN** a registered detection whose documentation was changed without regenerating the guide
- **WHEN** the guide is checked
- **THEN** the check fails, names the guide and the command that regenerates it, and points at where the two first disagree
